/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Encoder parameter sweep: compression level x row-filter strategy.
 *
 * One executable, no third-party dependencies beyond spng itself (and the
 * zlib it already links). All sample images are synthesized in-process.
 *
 * For every image it prints:
 *   - a 3 levels x 3 strategies size/time grid ("size-time" curve points)
 *   - the library default point (level 6 + adaptive ALL filtering)
 *   - a recommended point: fastest point whose encoded size is no more than
 *     1% larger than the default, checked against the >=25% time target
 *   - byte-for-byte reproducibility check for every configuration
 *   - a check that the emitted filter bytes match the selected strategy
 *
 * Finally it encodes a 4096x4096 image with the recommended configuration
 * and checks the < 3 s budget.
 */
#define _POSIX_C_SOURCE 199309L /* clock_gettime under -std=c99 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <zlib.h> /* IDAT is zlib-wrapped; zlib is an existing spng dependency */

#include "spng.h"

#define N_LEVELS 3
#define N_STRATS 3
#define N_IMAGES 4
#define SWEEP_W 512
#define SWEEP_H 512
#define BIG_W 4096
#define BIG_H 4096
#define N_REPEAT 5
#define BIG_REPEAT 3
#define TIME_BUDGET_S 3.0

/* Three points on the compression-level axis: fast / mid / library default.
   Level 4 is the "knee": for compressible content it keeps size within ~1%
   of the L6 default while removing most of the level-6 deflate cost. */
static const int levels[N_LEVELS] = { 1, 4, 6 };

struct filter_strategy
{
    const char *name;
    int filter_choice; /* SPNG_FILTER_CHOICE_* / SPNG_DISABLE_FILTERING */
};

static const struct filter_strategy strategies[N_STRATS] =
{
    { "none-fixed",   SPNG_DISABLE_FILTERING },
    { "paeth-fixed",  SPNG_FILTER_CHOICE_PAETH },
    { "adaptive-all", SPNG_FILTER_CHOICE_ALL },
};

static double now_seconds(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

static int cmp_double(const void *a, const void *b)
{
    double da = *(const double *)a, db = *(const double *)b;
    return (da > db) - (da < db);
}

/* deterministic PRNG so the whole run is reproducible */
static uint32_t rng_state;
static uint32_t xrnd(void)
{
    uint32_t x = rng_state;
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    rng_state = x;
    return x;
}

static void make_image(int kind, uint8_t *img, size_t w, size_t h)
{
    rng_state = 0x12345678u + (uint32_t)kind * 2654435761u;
    size_t x, y;
    for(y=0; y < h; y++)
    for(x=0; x < w; x++)
    {
        uint8_t *px = img + (y * w + x) * 4;
        uint8_t r, g, b;

        switch(kind)
        {
            case 0: /* smooth gradient: filtering + deflate win big */
                r = (uint8_t)(x * 255u / w);
                g = (uint8_t)(y * 255u / h);
                b = (uint8_t)((x + y) * 255u / (w + h));
                break;
            case 1: /* photo-like: smooth regions + mild camera noise */
                r = (uint8_t)(128 + 100.0 * (0.5 + 0.5 * (double)x / w) + (xrnd() % 13) - 6);
                g = (uint8_t)(128 + 100.0 * (0.5 + 0.5 * (double)y / h) + (xrnd() % 13) - 6);
                b = (uint8_t)(64 + 128.0 * (0.5 + 0.5 * (double)(x ^ y) / (w > h ? w : h)) + (xrnd() % 13) - 6);
                break;
            case 2: /* synthetic graphics: flat bands + sharp edges */
                if(((x / 32) + (y / 32)) % 2 == 0) { r = 240; g = 30; b = 90; }
                else if((x / 64) % 3 == 0) { r = 20; g = 200; b = 220; }
                else { r = 40; g = 40; b = 60; }
                break;
            default: /* noisy: high entropy, filtering barely helps */
                r = (uint8_t)(xrnd() & 0xff);
                g = (uint8_t)(xrnd() & 0xff);
                b = (uint8_t)(xrnd() & 0xff);
                break;
        }

        px[0] = r; px[1] = g; px[2] = b; px[3] = 255;
    }
}

static const char *img_name(int kind)
{
    static const char *names[N_IMAGES] =
        { "gradient", "photo-like", "graphics", "noisy" };
    return names[kind];
}

/* Encode one RGBA8 image with an explicit level/filter combination.
   Caller frees *out. Returns 0 on success. */
static int encode_once(const uint8_t *img, uint32_t w, uint32_t h,
                       int level, int filter_choice,
                       uint8_t **out, size_t *out_len)
{
    int err = 0;
    spng_ctx *ctx = spng_ctx_new(SPNG_CTX_ENCODER);
    if(ctx == NULL) return -1;

    struct spng_ihdr ihdr;
    memset(&ihdr, 0, sizeof(ihdr));
    ihdr.width = w;
    ihdr.height = h;
    ihdr.bit_depth = 8;
    ihdr.color_type = SPNG_COLOR_TYPE_TRUECOLOR_ALPHA;

    if(spng_set_ihdr(ctx, &ihdr)) goto fail;
    if(spng_set_option(ctx, SPNG_IMG_COMPRESSION_LEVEL, level)) goto fail;
    if(spng_set_option(ctx, SPNG_FILTER_CHOICE, filter_choice)) goto fail;
    if(spng_set_option(ctx, SPNG_ENCODE_TO_BUFFER, 1)) goto fail;

    if(spng_encode_image(ctx, img, (size_t)w * h * 4, SPNG_FMT_PNG,
                         SPNG_ENCODE_FINALIZE)) goto fail;

    *out = spng_get_png_buffer(ctx, out_len, &err);
    if(*out == NULL || err) goto fail;

    spng_ctx_free(ctx);
    return 0;

fail:
    spng_ctx_free(ctx);
    return -1;
}

/* Decode the PNG back through spng itself and compare against the source. */
static int roundtrip_matches(const uint8_t *png, size_t png_len,
                             const uint8_t *img, size_t w, size_t h)
{
    spng_ctx *ctx = spng_ctx_new(0);
    if(ctx == NULL) return -1;
    if(spng_set_png_buffer(ctx, png, png_len)) { spng_ctx_free(ctx); return -1; }

    size_t need = w * h * 4;
    uint8_t *dec = malloc(need);
    if(dec == NULL) { spng_ctx_free(ctx); return -1; }

    int rc = spng_decode_image(ctx, dec, need, SPNG_FMT_RGBA8, 0);
    if(rc) { free(dec); spng_ctx_free(ctx); return -1; }

    rc = memcmp(dec, img, need) == 0 ? 0 : -2;
    free(dec);
    spng_ctx_free(ctx);
    return rc;
}

/* Validate that every row's filter byte in the IDAT stream is legal for the
   selected strategy: all NONE when filtering is disabled, all PAETH for the
   fixed-paeth strategy. (IDAT is zlib-wrapped, so we use zlib's inflate.) */
static int filter_bytes_match(const uint8_t *png, size_t png_len,
                              uint32_t w, uint32_t h, int filter_choice)
{
    /* Concatenate IDAT payloads. Chunks start at offset 8 (after signature). */
    size_t cap = png_len, used = 0;
    uint8_t *raw = malloc(cap);
    if(raw == NULL) return -1;

    size_t off = 8;
    while(off + 8 <= png_len)
    {
        uint32_t clen = ((uint32_t)png[off] << 24) | ((uint32_t)png[off+1] << 16) |
                        ((uint32_t)png[off+2] << 8) | png[off+3];
        const uint8_t *type = png + off + 4;
        if(off + 12 + clen > png_len) { free(raw); return -1; }

        if(memcmp(type, "IDAT", 4) == 0)
        {
            if(used + clen > cap) { free(raw); return -1; }
            memcpy(raw + used, png + off + 8, clen);
            used += clen;
        }
        off += 12 + clen;
        if(memcmp(type, "IEND", 4) == 0) break;
    }

    const size_t rowbytes = (size_t)w * 4;
    const size_t expect = (rowbytes + 1) * h;
    uint8_t *inflated = malloc(expect);
    if(inflated == NULL) { free(raw); return -1; }

    z_stream zs;
    memset(&zs, 0, sizeof(zs));
    if(inflateInit(&zs) != Z_OK) { free(raw); free(inflated); return -1; }
    zs.next_in = raw; zs.avail_in = (uInt)used;
    zs.next_out = inflated; zs.avail_out = (uInt)expect;
    int zrc = inflate(&zs, Z_FINISH);
    inflateEnd(&zs);
    free(raw);
    if(zrc != Z_STREAM_END || zs.total_out != expect) { free(inflated); return -1; }

    int rc = 0;
    uint32_t y;
    for(y=0; y < h; y++)
    {
        int f = inflated[y * (rowbytes + 1)];
        if(filter_choice == SPNG_DISABLE_FILTERING)
        {
            if(f != SPNG_FILTER_NONE) { rc = -2; break; }
        }
        else if(filter_choice == SPNG_FILTER_CHOICE_PAETH)
        {
            if(f != SPNG_FILTER_PAETH) { rc = -2; break; }
        }
        else
        {
            if(f < 0 || f > 4) { rc = -2; break; }
        }
    }

    free(inflated);
    return rc;
}

struct point
{
    int level, strat_idx;
    size_t size;
    double median_s;
};

int main(void)
{
    const size_t sweep_n = (size_t)SWEEP_W * SWEEP_H * 4;
    uint8_t *img = malloc(sweep_n);
    if(img == NULL) return 2;

    int failures = 0;
    struct point recommended[N_IMAGES];

    printf("# spng encoder sweep: %dx%d RGBA8, %d levels x %d strategies, "
           "median of %d encodes per cell\n\n",
           SWEEP_W, SWEEP_H, N_LEVELS, N_STRATS, N_REPEAT);

    int kind;
    for(kind=0; kind < N_IMAGES; kind++)
    {
        make_image(kind, img, SWEEP_W, SWEEP_H);

        struct point grid[N_LEVELS][N_STRATS];
        struct point def = { 6, 2, 0, 0.0 };

        int li, si;
        for(li=0; li < N_LEVELS; li++)
        for(si=0; si < N_STRATS; si++)
        {
            int level = levels[li];
            int choice = strategies[si].filter_choice;

            uint8_t *buf1 = NULL, *buf2 = NULL;
            size_t len1 = 0, len2 = 0;
            double times[N_REPEAT];

            int rep;
            for(rep=0; rep < N_REPEAT; rep++)
            {
                uint8_t *buf = NULL; size_t len = 0;
                double t0 = now_seconds();
                if(encode_once(img, SWEEP_W, SWEEP_H, level, choice, &buf, &len))
                {
                    printf("FATAL: encode failed (%s L%d %s)\n",
                           img_name(kind), level, strategies[si].name);
                    return 2;
                }
                times[rep] = now_seconds() - t0;
                if(rep == 0) { buf1 = buf; len1 = len; }
                else free(buf);
            }

            /* reproducibility: a second encode must be byte-identical */
            if(encode_once(img, SWEEP_W, SWEEP_H, level, choice, &buf2, &len2) ||
               len2 != len1 || memcmp(buf1, buf2, len1) != 0)
            {
                printf("FAIL reproducibility: %s L%d %s\n",
                       img_name(kind), level, strategies[si].name);
                failures++;
            }
            free(buf2);

            if(roundtrip_matches(buf1, len1, img, SWEEP_W, SWEEP_H) != 0)
            {
                printf("FAIL roundtrip decode: %s L%d %s\n",
                       img_name(kind), level, strategies[si].name);
                failures++;
            }

            if(filter_bytes_match(buf1, len1, SWEEP_W, SWEEP_H, choice) != 0)
            {
                printf("FAIL filter-byte/strategy mismatch: %s L%d %s\n",
                       img_name(kind), level, strategies[si].name);
                failures++;
            }

            qsort(times, N_REPEAT, sizeof(double), cmp_double);
            grid[li][si].level = level;
            grid[li][si].strat_idx = si;
            grid[li][si].size = len1;
            grid[li][si].median_s = times[N_REPEAT / 2];
            free(buf1);
        }

        /* library default: level 6 + adaptive ALL */
        {
            double times[N_REPEAT];
            int rep;
            for(rep=0; rep < N_REPEAT; rep++)
            {
                uint8_t *buf = NULL; size_t len = 0;
                double t0 = now_seconds();
                if(encode_once(img, SWEEP_W, SWEEP_H, 6, SPNG_FILTER_CHOICE_ALL, &buf, &len))
                    return 2;
                times[rep] = now_seconds() - t0;
                if(rep == 0) def.size = len;
                free(buf);
            }
            qsort(times, N_REPEAT, sizeof(double), cmp_double);
            def.median_s = times[N_REPEAT / 2];
        }

        printf("## image %d/4: %s\n", kind + 1, img_name(kind));
        printf("default (L6 adaptive-all): %zu bytes, %.4f s\n\n",
               (unsigned long)def.size, def.median_s);
        printf("%-12s |", "level");
        for(si=0; si < N_STRATS; si++)
            printf(" %-22s |", strategies[si].name);
        printf("\n");
        for(li=0; li < N_LEVELS; li++)
        {
            printf("L%-11d |", levels[li]);
            for(si=0; si < N_STRATS; si++)
            {
                double dsize = 100.0 * ((double)grid[li][si].size / (double)def.size - 1.0);
                printf(" %6zu B %+6.2f%% %7.4fs |",
                       (unsigned long)grid[li][si].size, dsize, grid[li][si].median_s);
            }
            printf("\n");
        }

        /* recommendation: fastest point within +1% size of default. */
        const double size_limit = def.size * 1.01;
        const struct point *best = NULL;
        for(li=0; li < N_LEVELS; li++)
        for(si=0; si < N_STRATS; si++)
        {
            const struct point *p = &grid[li][si];
            if((double)p->size <= size_limit &&
               (best == NULL || p->median_s < best->median_s))
                best = p;
        }
        if(best == NULL) best = &grid[2][2]; /* fallback: default itself */

        recommended[kind] = *best;
        double speedup = 100.0 * (1.0 - best->median_s / def.median_s);
        double sizediff = 100.0 * ((double)best->size / (double)def.size - 1.0);
        int meets = (best->size <= (size_t)size_limit) && (speedup >= 25.0);

        printf("\nrecommended: L%d %s -> %zu bytes (%+.2f%% vs default), "
               "%.4f s (%.1f%% faster), acceptance(size<=+1%% & time>=25%%): %s\n\n",
               best->level, strategies[best->strat_idx].name,
               (unsigned long)best->size, sizediff, best->median_s, speedup,
               meets ? "PASS" : "FAIL");
        if(!meets) failures++;
    }

    /* 4096x4096 budget on the recommended point of each image kind */
    const size_t big_n = (size_t)BIG_W * BIG_H * 4;
    uint8_t *big = malloc(big_n);
    if(big == NULL) return 2;

    printf("## 4096x4096 timing (median of %d)\n", BIG_REPEAT);
    for(kind=0; kind < N_IMAGES; kind++)
    {
        make_image(kind, big, BIG_W, BIG_H);
        const struct point *r = &recommended[kind];

        double rt[BIG_REPEAT], dt[BIG_REPEAT];
        size_t rlen = 0, dlen = 0;
        int rep;
        for(rep=0; rep < BIG_REPEAT; rep++)
        {
            uint8_t *b; size_t l;
            double t0 = now_seconds();
            if(encode_once(big, BIG_W, BIG_H, r->level,
                           strategies[r->strat_idx].filter_choice, &b, &l)) return 2;
            rt[rep] = now_seconds() - t0;
            if(rep == 0) rlen = l;
            free(b);

            t0 = now_seconds();
            if(encode_once(big, BIG_W, BIG_H, 6, SPNG_FILTER_CHOICE_ALL, &b, &l)) return 2;
            dt[rep] = now_seconds() - t0;
            if(rep == 0) dlen = l;
            free(b);
        }
        qsort(rt, BIG_REPEAT, sizeof(double), cmp_double);
        qsort(dt, BIG_REPEAT, sizeof(double), cmp_double);

        int within = rt[BIG_REPEAT / 2] < TIME_BUDGET_S;
        printf("%-11s recommended L%d %-12s: %.4f s (%zu B) [%s] ; "
               "default: %.4f s (%zu B), speedup %.1f%%\n",
               img_name(kind), r->level, strategies[r->strat_idx].name,
               rt[BIG_REPEAT / 2], (unsigned long)rlen,
               within ? "under 3s" : "OVER BUDGET",
               dt[BIG_REPEAT / 2], (unsigned long)dlen,
               100.0 * (1.0 - rt[BIG_REPEAT / 2] / dt[BIG_REPEAT / 2]));
        if(!within) failures++;
    }

    free(big);
    free(img);

    printf("\n%s\n", failures == 0 ? "ALL CHECKS PASSED" : "CHECKS FAILED");
    return failures == 0 ? 0 : 1;
}
