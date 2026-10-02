#define _POSIX_C_SOURCE 199309L
#include <time.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hash.h"
#include "kem.h"
#include "pke.h"
#include "encode.h"
#include "pack.h"
#include "sample.h"
#include "scloudplus_param_common.h"

static size_t generated_bytes;

static void counted_shake128(uint8_t *out, size_t blocks, keccak_state *state)
{
    generated_bytes += blocks * SHAKE128_RATE;
    shake128_squeezeblocks(out, blocks, state);
}

static void counted_shake256(uint8_t *out, size_t blocks, keccak_state *state)
{
    generated_bytes += blocks * SHAKE256_RATE;
    shake256_squeezeblocks(out, blocks, state);
}

/* Use a separate instrumented copy only for selecting input profiles. */
#define shake128_squeezeblocks counted_shake128
#define shake256_squeezeblocks counted_shake256
#define sample_s profile_sample_s
#define sample_sp profile_sample_sp
#define sample_e profile_sample_e
#define sample_e12 profile_sample_e12
#include "sample.c"
#undef sample_s
#undef sample_sp
#undef sample_e
#undef sample_e12
#undef shake128_squeezeblocks
#undef shake256_squeezeblocks

typedef struct {
    uint64_t id;
    size_t generated;
    size_t rounds_s;
    size_t rounds_e;
    uint8_t message[scloudplus_ss];
    uint8_t seed[scloudplus_pke_enc_expand_bytes];
    uint8_t ct[scloudplus_ctx];
} probe;

static volatile uint64_t sink;

static uint64_t rng_state = UINT64_C(0x9e3779b97f4a7c15);

static uint64_t next_random(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}

static uint64_t mono_ns(void){
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec*1000000000ULL + (uint64_t)ts.tv_nsec;
}
static double nanos(uint64_t ticks)
{
    return (double)ticks;
}

static void prepare(probe *p, uint64_t id, const uint8_t *pk)
{
    uint8_t input[scloudplus_ss + scloudplus_hash_bytes];
    uint8_t rk[scloudplus_G_bytes];
    const size_t ns = (size_t)scloudplus_mbar * scloudplus_m;
    const size_t ne = (size_t)scloudplus_mbar *
        ((size_t)scloudplus_n + scloudplus_nbar);
    uint16_t s[ns], e[ne];
    sample_reject_reader sr, er;

    memset(p, 0, sizeof(*p));
    memset(input, 0, sizeof(input));
    p->id = id;
    for (unsigned j = 0; j < 8; j++) input[j] = (uint8_t)(id >> (8*j));
    memcpy(p->message, input, sizeof(p->message));
    scloudplus_H(input + scloudplus_ss, pk, scloudplus_pk);
    scloudplus_G(rk, input, sizeof(input));
    scloudplus_F(p->seed, sizeof(p->seed), rk, scloudplus_pke_enc_coins_bytes);

    generated_bytes = 0;
    sample_reject_reader_init(&sr, p->seed, scloudplus_pke_enc_r1_bytes);
    sample_bd6_from_reader(&sr, ns, s);
    p->rounds_s = (generated_bytes - sr.reader.block_len + sr.reader.block_pos) / 96;
    const size_t generated_s = generated_bytes;
    sample_reject_reader_init(&er, p->seed + scloudplus_pke_enc_r1_bytes,
                              scloudplus_pke_enc_r2_bytes);
    sample_bd6_from_reader(&er, ne, e);
    p->rounds_e = (generated_bytes - generated_s - er.reader.block_len +
                   er.reader.block_pos) / 96;
    p->generated = generated_bytes;

    uint16_t encoded[(size_t)scloudplus_mbar * scloudplus_nbar];
    msg_encode(p->message, encoded);
    pack_c2(encoded, p->ct + scloudplus_c1);
}

static uint64_t run_sampler(const probe *p)
{
    const size_t ns = (size_t)scloudplus_mbar * scloudplus_m;
    const size_t ne1 = (size_t)scloudplus_mbar * scloudplus_n;
    const size_t ne = ne1 + (size_t)scloudplus_mbar * scloudplus_nbar;
    uint16_t s[ns], e[ne];
    const uint64_t start = mono_ns();
    sample_sp(p->seed, scloudplus_pke_enc_r1_bytes, s);
    sample_e12(p->seed + scloudplus_pke_enc_r1_bytes,
               scloudplus_pke_enc_r2_bytes, e, e + ne1);
    const uint64_t end = mono_ns();
    sink += s[0] + e[0];
    return end - start;
}

static uint64_t run_decaps(const probe *p, const uint8_t *sk)
{
    uint8_t ss[scloudplus_ss];
    const uint64_t start = mono_ns();
    scloud_kemdecaps(sk, p->ct, ss);
    const uint64_t end = mono_ns();
    sink += ss[0];
    return end - start;
}

int main(int argc, char **argv)
{
    const unsigned blocks = argc > 1 ? (unsigned)strtoul(argv[1], 0, 10) : 200;
    const unsigned pairs = argc > 2 ? (unsigned)strtoul(argv[2], 0, 10) : 40;
    const unsigned search = argc > 3 ? (unsigned)strtoul(argv[3], 0, 10) : 4096;
    const int raw_mode = argc > 4 && !strcmp(argv[4], "raw");
    if (!blocks || !pairs || !search ) return 1;
    uint8_t pk[scloudplus_pk], sk[scloudplus_kem_sk];
    if (scloud_kemkeygen(pk, sk)) return 2;
    probe *tmp = malloc(sizeof(*tmp));
    probe *low = malloc(sizeof(*low));
    probe *high = malloc(sizeof(*high));
    probe *zero = malloc(sizeof(*zero));
    if (!tmp || !low || !high || !zero) return 3;
    prepare(zero, 0, pk);
    *low = *zero;
    *high = *zero;
    for (unsigned i = 1; i < search; i++) {
        prepare(tmp, i, pk);
        if (tmp->generated < low->generated ||
            (tmp->generated == low->generated &&
             tmp->rounds_s + tmp->rounds_e < low->rounds_s + low->rounds_e))
            *low = *tmp;
        if (tmp->generated > high->generated ||
            (tmp->generated == high->generated &&
             tmp->rounds_s + tmp->rounds_e > high->rounds_s + high->rounds_e))
            *high = *tmp;
    }
    if (low->generated == high->generated) return 4;
    const probe *p[] = {low, high, zero};
    for (unsigned j = 0; j < 3; j++) {
        uint8_t recovered[scloudplus_ss];
        uint8_t input[scloudplus_ss + scloudplus_hash_bytes], rk[scloudplus_G_bytes];
        uint8_t ct1[scloudplus_ctx];
        pke_dec(sk, p[j]->ct, recovered);
        if (memcmp(recovered, p[j]->message, sizeof(recovered))) return 5;
        memcpy(input, p[j]->message, sizeof(p[j]->message));
        scloudplus_H(input + scloudplus_ss, pk, sizeof(pk));
        scloudplus_G(rk, input, sizeof(input));
        pke_enc(pk, p[j]->message, rk, ct1);
        if (!memcmp(ct1, p[j]->ct, sizeof(ct1))) return 6;
        for (unsigned i = 0; i < 100; i++) {
            (void)run_sampler(p[j]);
            (void)run_decaps(p[j], sk);
        }
    }
    fprintf(stderr, "low id=%llu rounds=%zu+%zu generated=%zu; "
            "high id=%llu rounds=%zu+%zu generated=%zu; "
            "zero id=%llu rounds=%zu+%zu generated=%zu\n",
            (unsigned long long)low->id, low->rounds_s, low->rounds_e,
            low->generated, (unsigned long long)high->id,
            high->rounds_s, high->rounds_e, high->generated,
            (unsigned long long)zero->id, zero->rounds_s,
            zero->rounds_e, zero->generated);
    if (raw_mode) {
        /* Emit individual (un-averaged) decaps timings for low & high, interleaved,
         * so the distribution shape (gaussian vs heavy-tailed) can be studied. */
        const unsigned samples = blocks * pairs;
        puts("i,low_ns,high_ns");
        for (unsigned i = 0; i < samples; i++) {
            /* randomize order within each pair to avoid position bias */
            double a, b;
            if (next_random() & 1) {
                a = nanos(run_decaps(low, sk));
                b = nanos(run_decaps(high, sk));
            } else {
                b = nanos(run_decaps(high, sk));
                a = nanos(run_decaps(low, sk));
            }
            printf("%u,%.1f,%.1f\n", i, a, b);
        }
        fprintf(stderr, "sink=%llu\n", (unsigned long long)sink);
        free(tmp); free(low); free(high); free(zero);
        return 0;
    }
    puts("mode,block,low_ns,high_ns,zero_ns,high_minus_low_ns");
    for (unsigned mode = 0; mode < 2; mode++) {
        for (unsigned block = 0; block < blocks; block++) {
            double totals[3] = {0, 0, 0};
            for (unsigned pair = 0; pair < pairs; pair++) {
                unsigned order[3] = {0, 1, 2};
                for (unsigned k = 2; k > 0; k--) {
                    unsigned j = (unsigned)(next_random() % (k + 1));
                    unsigned swap = order[k]; order[k] = order[j]; order[j] = swap;
                }
                for (unsigned k = 0; k < 3; k++) {
                    unsigned j = order[k];
                    totals[j] += nanos(mode == 0 ? run_sampler(p[j]) :
                                       run_decaps(p[j], sk));
                }
            }
            printf("%s,%u,%.3f,%.3f,%.3f,%.3f\n",
                   mode == 0 ? "sampler" : "decaps", block,
                   totals[0] / pairs, totals[1] / pairs,
                   totals[2] / pairs, (totals[1] - totals[0]) / pairs);
            fflush(stdout);
        }
    }
    fprintf(stderr, "sink=%llu\n", (unsigned long long)sink);
    free(tmp); free(low); free(high); free(zero);
    return 0;
}
