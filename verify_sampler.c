#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hash.h"
#include "scloudplus_param_common.h"
#if defined(VERIFY_FULL_KEM)
#include "kem.h"
#include "pke.h"
#include "encode.h"
#include "pack.h"
#endif

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

/* Include the original sampler to inspect its final reader positions. */
#define shake128_squeezeblocks counted_shake128
#define shake256_squeezeblocks counted_shake256
#include "sample.c"
#undef shake128_squeezeblocks
#undef shake256_squeezeblocks

typedef struct {
    size_t consumed;
    size_t generated;
    size_t rounds;
} profile;

static profile inspect_stream(const uint8_t *seed, size_t seedlen,
                              size_t coeffs, unsigned bd, uint16_t *out)
{
    profile p = {0, 0, 0};
    generated_bytes = 0;
#if defined(SAMPLE_REJECT_BITS_CAPACITY)
    sample_reject_reader r;
    sample_reject_reader_init(&r, seed, seedlen);
#if SCLOUDPLUS_SAMPLE_SECRET_BD == 6
    sample_bd6_from_reader(&r, coeffs, out);
    const size_t batch = 96;
#else
    sample_bd12_from_reader(&r, coeffs, out);
    const size_t batch = 128;
#endif
    p.generated = generated_bytes;
    p.consumed = p.generated - r.reader.block_len + r.reader.block_pos;
    p.rounds = p.consumed / batch;
    (void)bd;
#else
    sample_reader r;
    reader_init(&r, seed, seedlen);
#if SCLOUDPLUS_SAMPLE_SECRET_BD == 4
    if (bd == 4) sample_bd4_from_reader(&r, coeffs, out);
    else
#endif
        sample_bd2_from_reader(&r, coeffs, out);
    p.generated = generated_bytes;
    p.consumed = p.generated - r.block_len + r.block_pos;
    (void)bd;
#endif
    return p;
}

int main(int argc, char **argv)
{
    const size_t trials = argc > 1 ? (size_t)strtoul(argv[1], NULL, 10) : 512;
    const size_t ns = (size_t)scloudplus_mbar * scloudplus_m;
    const size_t ne1 = (size_t)scloudplus_mbar * scloudplus_n;
    const size_t ne = ne1 + (size_t)scloudplus_mbar * scloudplus_nbar;
    uint8_t pk[scloudplus_pk];
    uint8_t input[scloudplus_ss + scloudplus_hash_bytes];
    uint8_t rk[scloudplus_G_bytes], seed[scloudplus_pke_enc_expand_bytes];
    uint16_t s[ns], e[ne], actual_s[ns], actual_e[ne];
#if defined(VERIFY_FULL_KEM)
    uint8_t sk[scloudplus_kem_sk];
    size_t first_generated = (size_t)-1;
    int distinct_checked = 0;
    if (scloud_kemkeygen(pk, sk) != 0) return 1;
#else
    memset(pk, 0, sizeof(pk));
#endif
    memset(input, 0, sizeof(input));
    scloudplus_H(input + scloudplus_ss, pk, sizeof(pk));
    puts("message_counter,rounds_s,rounds_e,consumed,generated,coeff_digest");
    for (size_t i = 0; i < trials; i++) {
        for (unsigned j = 0; j < 8; j++) input[j] = (uint8_t)((uint64_t)i >> (8*j));
        scloudplus_G(rk, input, sizeof(input));
        scloudplus_F(seed, sizeof(seed), rk, scloudplus_pke_enc_coins_bytes);
        profile ps = inspect_stream(seed, scloudplus_pke_enc_r1_bytes,
                                    ns, scloudplus_secret_bd, s);
        profile pe = inspect_stream(seed + scloudplus_pke_enc_r1_bytes,
                                    scloudplus_pke_enc_r2_bytes,
                                    ne, scloudplus_error_bd, e);
        generated_bytes = 0;
        sample_sp(seed, scloudplus_pke_enc_r1_bytes, actual_s);
        sample_e12(seed + scloudplus_pke_enc_r1_bytes,
                   scloudplus_pke_enc_r2_bytes, actual_e, actual_e + ne1);
        if (generated_bytes != ps.generated + pe.generated ||
            memcmp(s, actual_s, sizeof(s)) || memcmp(e, actual_e, sizeof(e))) {
            fputs("Original public sampler disagrees with inspected reader\n", stderr);
            return 1;
        }
#if defined(VERIFY_FULL_KEM)
        const size_t expected_generated = ps.generated + pe.generated;
        if (first_generated == (size_t)-1) first_generated = expected_generated;
        if (i < 8 || (!distinct_checked && expected_generated != first_generated)) {
            uint8_t ct[scloudplus_ctx], ct1[scloudplus_ctx];
            uint8_t recovered[scloudplus_ss], ss[scloudplus_ss], ss2[scloudplus_ss];
            uint16_t encoded[(size_t)scloudplus_mbar * scloudplus_nbar];
            memset(ct, 0, sizeof(ct));
            msg_encode(input, encoded);
            pack_c2(encoded, ct + scloudplus_c1);
            pke_dec(sk, ct, recovered);
            if (memcmp(recovered, input, sizeof(recovered))) return 2;
            pke_enc(pk, input, rk, ct1);
            if (!memcmp(ct, ct1, sizeof(ct))) return 3;
            generated_bytes = 0;
            scloud_kemdecaps(sk, ct, ss);
            const size_t first = generated_bytes;
            generated_bytes = 0;
            scloud_kemdecaps(sk, ct, ss2);
            if (first != expected_generated || generated_bytes != first ||
                memcmp(ss, ss2, sizeof(ss))) return 4;
            if (expected_generated != first_generated) distinct_checked = 1;
            fprintf(stderr, "invalid ciphertext %zu: decoded m, re-encryption mismatch, "
                    "sampler generated %zu bytes, deterministic replay PASS\n", i, first);
        }
#endif
        uint64_t digest = UINT64_C(14695981039346656037);
        for (size_t k = 0; k < ns + ne; k++) {
            digest ^= k < ns ? s[k] : e[k - ns];
            digest *= UINT64_C(1099511628211);
        }
        printf("%zu,%zu,%zu,%zu,%zu,%016llx\n", i, ps.rounds, pe.rounds,
               ps.consumed + pe.consumed, ps.generated + pe.generated,
               (unsigned long long)digest);
    }
#if defined(VERIFY_FULL_KEM)
    if (trials >= 256 && !distinct_checked) {
        fputs("No second generated-byte count reached actual decapsulation\n", stderr);
        return 5;
    }
#endif
    return 0;
}
