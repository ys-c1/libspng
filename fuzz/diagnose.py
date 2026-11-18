#!/usr/bin/env python3
"""Diagnostic: which decoder outcomes do our mutations actually reach?

The harness swallows SPNG error codes, so we use a separate instrumented
build that prints the return codes of spng_decoded_image_size() and
spng_decode_image(). This tells us whether mutations reach deep decode
paths or get rejected at header validation.
"""
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

from rng import Rng
from fuzz_driver import load_seeds, plan_input

DIAG_SRC = r'''
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include "spng.h"

/* mirror of the harness buffer reader */
struct bs { const uint8_t *d; size_t n; };
static int rd(spng_ctx *ctx, void *user, void *dest, size_t len){
    struct bs *s=user; (void)ctx;
    if(len>s->n) return SPNG_IO_EOF;
    memcpy(dest,s->d,len); s->n-=len; s->d+=len; return 0;
}

static int rf(uint8_t*b,size_t n){size_t o=0;while(o<n){ssize_t r=read(0,b+o,n-o);if(r<=0)return -1;o+=(size_t)r;}return 0;}
static int wf(const uint8_t*b,size_t n){size_t o=0;while(o<n){ssize_t r=write(1,b+o,n-o);if(r<=0)return -1;o+=(size_t)r;}return 0;}

int main(void){
    uint8_t hdr[4];
    for(;;){
        if(rf(hdr,4))return 0;
        uint32_t n=(uint32_t)hdr[0]|((uint32_t)hdr[1]<<8)|((uint32_t)hdr[2]<<16)|((uint32_t)hdr[3]<<24);
        if(n==0||n>64u*1024u*1024u)return 0;
        uint8_t*buf=malloc(n); if(!buf)return 2;
        if(rf(buf,n)){free(buf);return 0;}
        if(n<4){free(buf);continue;}
        int fmt = buf[n-3] | (buf[n-2]<<8);
        int stream = buf[n-4]&1;
        int progressive = buf[n-4]&2;
        size_t sz=n-4;
        spng_ctx*ctx=spng_ctx_new(SPNG_CTX_IGNORE_ADLER32);
        struct bs st={buf,sz};
        if(stream) spng_set_png_stream(ctx,rd,&st);
        else spng_set_png_buffer(ctx,buf,sz);
        spng_set_image_limits(ctx,200000,200000);
        spng_set_chunk_limits(ctx,4*1000*1000,8*1000*1000);
        size_t out_size=0;
        int r1=spng_decoded_image_size(ctx,fmt,&out_size);
        int r2=0;
        if(!r1 && out_size<=80000000){
            unsigned char*out=malloc(out_size);
            if(progressive){
                r2=spng_decode_image(ctx,NULL,0,fmt,SPNG_DECODE_PROGRESSIVE);
                struct spng_row_info ri;
                int guard=0;
                while(!r2 && guard++ < 200005){
                    if(spng_get_row_info(ctx,&ri))break;
                    r2=spng_decode_row(ctx,out,out_size);
                }
            } else {
                r2=spng_decode_image(ctx,out,out_size,fmt,0);
            }
            free(out);
        } else r2=-999;
        spng_ctx_free(ctx); free(buf);
        uint8_t reply[9];
        memcpy(reply,&r1,4); memcpy(reply+4,&r2,4); reply[8]=0;
        if(wf(reply,9))return 0;
    }
}
'''


def build_diag():
    outdir = os.path.join(ROOT, "artifacts", "fuzz", "diag_build")
    os.makedirs(outdir, exist_ok=True)
    src = os.path.join(outdir, "diag.c")
    exe = os.path.join(outdir, "diag_worker")
    with open(src, "w") as f:
        f.write(DIAG_SRC)
    if not os.path.exists(exe):
        subprocess.run(["gcc", "-O1", "-g1", "-I", os.path.join(ROOT, "spng"),
                        src, os.path.join(ROOT, "spng", "spng.c"),
                        "-lz", "-lm", "-o", exe], check=True)
    return exe


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 20000
    seed = int(sys.argv[2]) if len(sys.argv) > 2 else 20261119
    exe = build_diag()
    seeds = load_seeds()
    rng = Rng(seed)
    from collections import Counter
    c1, c2, reached_decode = Counter(), Counter(), 0
    proc = subprocess.Popen([exe], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, bufsize=0)
    import struct as st
    for i in range(n):
        _, _, png, sfx = plan_input(rng, seeds)
        data = png + sfx
        proc.stdin.write(len(data).to_bytes(4, "little") + data)
        proc.stdin.flush()
        reply = proc.stdout.read(9)
        if len(reply) != 9:
            print("diag worker died at", i)
            break
        a = st.unpack("i", reply[0:4])[0]
        b = st.unpack("i", reply[4:8])[0]
        c1[a] += 1
        c2[b] += 1
        if a == 0:
            reached_decode += 1
    proc.stdin.close()
    proc.wait(timeout=5)
    print(f"iterations={n}  passed spng_decoded_image_size: {reached_decode} "
          f"({100*reached_decode/n:.1f}%)")
    print("spng_decoded_image_size rc histogram:", dict(sorted(c1.items())))
    print("spng_decode_image rc histogram       :", dict(sorted(c2.items())))


if __name__ == "__main__":
    main()
