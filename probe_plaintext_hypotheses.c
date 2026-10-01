#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "encode.h"
#include "hash.h"
#include "kem.h"
#include "pack.h"
#include "pke.h"
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

#define shake128_squeezeblocks counted_shake128
#define shake256_squeezeblocks counted_shake256
#include "sample.c"
#undef shake128_squeezeblocks
#undef shake256_squeezeblocks

typedef struct {
    size_t generated;
    size_t rounds;
} sampler_profile;

static sampler_profile profile_message(const uint8_t *pk, const uint8_t *message)
{
    uint8_t input[scloudplus_ss + scloudplus_hash_bytes];
    uint8_t rk[scloudplus_G_bytes];
    uint8_t seed[scloudplus_pke_enc_expand_bytes];
    uint16_t sp[(size_t)scloudplus_mbar * scloudplus_m];
    uint16_t e[(size_t)scloudplus_mbar *
               ((size_t)scloudplus_n + scloudplus_nbar)];
    sample_reject_reader sr, er;
    memcpy(input, message, scloudplus_ss);
    scloudplus_H(input + scloudplus_ss, pk, scloudplus_pk);
    scloudplus_G(rk, input, sizeof(input));
    scloudplus_F(seed, sizeof(seed), rk, scloudplus_pke_enc_coins_bytes);
    generated_bytes = 0;
    sample_reject_reader_init(&sr, seed, scloudplus_pke_enc_r1_bytes);
    sample_bd6_from_reader(&sr, (size_t)scloudplus_mbar * scloudplus_m, sp);
    const size_t first_generated = generated_bytes;
    const size_t first_read = first_generated - sr.reader.block_len +
                              sr.reader.block_pos;
    sample_reject_reader_init(&er, seed + scloudplus_pke_enc_r1_bytes,
                              scloudplus_pke_enc_r2_bytes);
    sample_bd6_from_reader(&er, (size_t)scloudplus_mbar *
                           ((size_t)scloudplus_n + scloudplus_nbar), e);
    const size_t second_read = generated_bytes - first_generated -
                               er.reader.block_len + er.reader.block_pos;
    return (sampler_profile){generated_bytes,
                             first_read / 96 + second_read / 96};
}

static uint64_t fingerprint(const uint8_t *bytes, size_t length)
{
    uint64_t h = UINT64_C(14695981039346656037);
    for (size_t i = 0; i < length; i++) {
        h ^= bytes[i];
        h *= UINT64_C(1099511628211);
    }
    return h;
}

int main(int argc, char **argv)
{
    uint8_t pk[scloudplus_pk], sk[scloudplus_kem_sk];
    uint8_t ct[scloudplus_ctx], actual[scloudplus_ss];
    uint16_t c1[(size_t)scloudplus_mbar * scloudplus_n] = {0};
    uint16_t c2[(size_t)scloudplus_mbar * scloudplus_nbar] = {0};
    uint16_t secret[(size_t)scloudplus_n * scloudplus_nbar];
    uint16_t d[(size_t)scloudplus_mbar * scloudplus_nbar];
    uint8_t predicted[scloudplus_ss];
    uint8_t zero_vector_message[scloudplus_ss];
    uint8_t baseline[scloudplus_ss] = {0};
    unsigned long baseline_id = argc > 1 ? strtoul(argv[1], 0, 10) : 0;
    if (baseline_id) {
        uint64_t state = UINT64_C(0x9e3779b97f4a7c15) ^ baseline_id;
        for (size_t i = 0; i < sizeof(baseline); i++) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            baseline[i] = (uint8_t)state;
        }
    }
    msg_encode(baseline, c2);
    if (argc > 2) c2[0] = (uint16_t)((c2[0] + strtoul(argv[2], 0, 10)) &
                                      scloudplus_q_mask);
    msg_decode(c2, zero_vector_message);
    const sampler_profile zero_vector_work = profile_message(pk, zero_vector_message);
    if (scloud_kemkeygen(pk, sk)) return 1;
    unpack_sk(sk, secret);
    puts("a,actual_s0,actual_message_digest,actual_is_zero,"
         "minus1_digest,zero_digest,plus1_digest,predictions_distinct,"
         "minus1_generated,zero_generated,plus1_generated,"
         "zero_vector_generated,actual_generated,zero_vector_matches_actual,"
         "minus1_rounds,zero_rounds,plus1_rounds,zero_vector_rounds,actual_rounds");
    for (unsigned a = 1; a < scloudplus_q; a++) {
        memset(c1, 0, sizeof(c1));
        c1[0] = (uint16_t)a;
        pack_c1(c1, ct);
        pack_c2(c2, ct + scloudplus_c1);
        pke_dec(sk, ct, actual);
        uint64_t digests[3];
        sampler_profile work[3];
        for (int guess = -1; guess <= 1; guess++) {
            memcpy(d, c2, sizeof(d));
            for (unsigned j = 0; j < scloudplus_nbar; j++) {
                int coefficient = j == 0 ? guess :
                    (int)(int16_t)secret[(size_t)j * scloudplus_n];
                d[j] = (uint16_t)(d[j] - (uint32_t)a * (uint32_t)coefficient);
            }
            msg_decode(d, predicted);
            digests[guess + 1] = fingerprint(predicted, sizeof(predicted));
            work[guess + 1] = profile_message(pk, predicted);
            if (guess == (int)(int16_t)secret[0] &&
                memcmp(predicted, actual, sizeof(actual))) return 2;
        }
        unsigned is_zero = 1;
        for (size_t i = 0; i < sizeof(actual); i++) is_zero &= actual[i] == 0;
        const sampler_profile actual_work = profile_message(pk, actual);
        printf("%u,%d,%016llx,%u,%016llx,%016llx,%016llx,%u,%zu,%zu,%zu,%zu,%zu,%u,%zu,%zu,%zu,%zu,%zu\n", a,
               (int)(int16_t)secret[0],
               (unsigned long long)fingerprint(actual, sizeof(actual)), is_zero,
               (unsigned long long)digests[0],
               (unsigned long long)digests[1],
               (unsigned long long)digests[2],
               digests[0] != digests[1] || digests[1] != digests[2],
               work[0].generated, work[1].generated, work[2].generated,
               zero_vector_work.generated, actual_work.generated,
               !memcmp(zero_vector_message, actual, sizeof(actual)),
               work[0].rounds, work[1].rounds, work[2].rounds,
               zero_vector_work.rounds, actual_work.rounds);
    }
    return 0;
}
