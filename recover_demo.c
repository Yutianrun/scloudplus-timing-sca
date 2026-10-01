/* Perfect-oracle, NOISELESS information-theoretic upper-bound demo.
 *
 * Goal: given a real (pk,sk), recover the first secret column
 *   g* = (center(S[0*n+0]), ..., center(S[(nbar-1)*n+0]))   (11 trits)
 * using ONLY what a timing attacker observes: the FO re-encryption sampler's
 * refill bucket = generated_bytes/544.
 *
 * Oracle (real): for a probe (C1,C2), build ct, run the real pke_dec(sk,ct)->m,
 * then the re-encryption sampler on m||H(pk); bucket is what timing reveals.
 *
 * Attacker (offline): for each candidate column g in {-1,0,1}^11, predict the
 * same bucket by Decode(C2 - alpha*g over the driven rows) -> m(g) -> sampler.
 * H(pk) is public, so this is fully offline. Keep candidates whose predicted
 * bucket matches the observed bucket for EVERY probe; the surviving set is g*'s
 * equivalence class. We report |class| vs #probes for two granularities:
 *   - bucket  (544B refill): what timing can actually see
 *   - rounds  (96B batch):   idealized upper bound timing CANNOT see
 *
 * This measures whether the INFORMATION suffices (no measurement noise). It is
 * an upper bound on a real attack, not a demonstrated key recovery.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "encode.h"
#include "hash.h"
#include "kem.h"
#include "pack.h"
#include "pke.h"
#include "scloudplus_param_common.h"

static size_t generated_bytes;
static void counted_shake128(uint8_t *out, size_t blocks, keccak_state *state)
{ generated_bytes += blocks * SHAKE128_RATE; shake128_squeezeblocks(out, blocks, state); }
static void counted_shake256(uint8_t *out, size_t blocks, keccak_state *state)
{ generated_bytes += blocks * SHAKE256_RATE; shake256_squeezeblocks(out, blocks, state); }
#define shake128_squeezeblocks counted_shake128
#define shake256_squeezeblocks counted_shake256
#include "sample.c"
#undef shake128_squeezeblocks
#undef shake256_squeezeblocks

/* Global memo: profile_message is a pure fn of m (pk fixed), and Decode is
 * many-to-one, so the ~177k candidate codes collapse to far fewer distinct
 * messages. Cache m -> (bucket,rounds) with open-addressed FNV-1a. */
#define MEMO_BITS 21
#define MEMO_SLOTS (1u << MEMO_BITS)
#define MEMO_MASK (MEMO_SLOTS - 1u)
static struct { uint8_t key[scloudplus_ss]; uint32_t b, r; uint8_t used; } *memo;
static size_t memo_hits, memo_miss;
static uint32_t memo_h(const uint8_t *m)
{
    uint32_t h = 2166136261u;
    for (unsigned i = 0; i < scloudplus_ss; i++) { h ^= m[i]; h *= 16777619u; }
    return h & MEMO_MASK;
}

static void profile_compute(const uint8_t *pk, const uint8_t *message,
                            size_t *bucket, size_t *rounds);
/* Sampler profile of a candidate message: bucket (544B) and rounds (96B). */
static void profile_message(const uint8_t *pk, const uint8_t *message,
                            size_t *bucket, size_t *rounds)
{
    if (memo) {
        uint32_t i = memo_h(message);
        for (unsigned probe = 0; probe < 64; probe++) {
            if (!memo[i].used) break;
            if (!memcmp(memo[i].key, message, scloudplus_ss)) {
                *bucket = memo[i].b; *rounds = memo[i].r; memo_hits++; return;
            }
            i = (i + 1) & MEMO_MASK;
        }
        size_t b, r; profile_compute(pk, message, &b, &r);
        if (!memo[i].used) {
            memo[i].used = 1; memcpy(memo[i].key, message, scloudplus_ss);
            memo[i].b = (uint32_t)b; memo[i].r = (uint32_t)r;
        }
        *bucket = b; *rounds = r; memo_miss++; return;
    }
    profile_compute(pk, message, bucket, rounds);
}

static void profile_compute(const uint8_t *pk, const uint8_t *message,
                            size_t *bucket, size_t *rounds)
{
    uint8_t input[scloudplus_ss + scloudplus_hash_bytes];
    uint8_t rk[scloudplus_G_bytes];
    uint8_t seed[scloudplus_pke_enc_expand_bytes];
    const size_t ns = (size_t)scloudplus_mbar * scloudplus_m;
    const size_t ne = (size_t)scloudplus_mbar *
        ((size_t)scloudplus_n + scloudplus_nbar);
    uint16_t s[ns], e[ne];
    sample_reject_reader sr, er;
    memcpy(input, message, scloudplus_ss);
    scloudplus_H(input + scloudplus_ss, pk, scloudplus_pk);
    scloudplus_G(rk, input, sizeof(input));
    scloudplus_F(seed, sizeof(seed), rk, scloudplus_pke_enc_coins_bytes);
    generated_bytes = 0;
    sample_reject_reader_init(&sr, seed, scloudplus_pke_enc_r1_bytes);
    sample_bd6_from_reader(&sr, ns, s);
    const size_t first = generated_bytes;
    const size_t first_read = first - sr.reader.block_len + sr.reader.block_pos;
    sample_reject_reader_init(&er, seed + scloudplus_pke_enc_r1_bytes,
                              scloudplus_pke_enc_r2_bytes);
    sample_bd6_from_reader(&er, ne, e);
    const size_t second_read = generated_bytes - first -
                               er.reader.block_len + er.reader.block_pos;
    *bucket = generated_bytes / 544;
    *rounds = first_read / 96 + second_read / 96;
}

static inline int center(uint16_t v)
{
    int r = v & scloudplus_q_mask;
    return r >= (1 << (scloudplus_logq - 1)) ? r - (1 << scloudplus_logq) : r;
}

static uint64_t rng = 0x243f6a8885a308d3ULL;
static uint64_t xr(void){ rng^=rng<<13; rng^=rng>>7; rng^=rng<<17; return rng; }

/* Deterministic key RNG, SEPARATE from the probe stream `rng`, so a fixed
 * key-seed yields the SAME secret across random and adaptive runs (keygen draws
 * happen before any probe selection). Overrides random.c -> drop it from link. */
static uint64_t krng = 0x9e3779b97f4a7c15ULL;
static uint64_t kx(void){ krng^=krng<<13; krng^=krng>>7; krng^=krng<<17; return krng; }
int randombytes(unsigned char *buf, unsigned int size)
{
    for (unsigned i = 0; i < size; i++) buf[i] = (unsigned char)(kx() >> 33);
    return 0;
}

int main(int argc, char **argv)
{
    const unsigned nprobes = argc > 1 ? (unsigned)strtoul(argv[1], 0, 10) : 80U;
    if (argc > 2) rng = strtoull(argv[2], 0, 10) | 1ULL;
    /* argv[5] = key seed: hold the secret fixed while varying probe strategy */
    if (argc > 5) krng = strtoull(argv[5], 0, 10) | 1ULL;
    uint8_t pk[scloudplus_pk], sk[scloudplus_kem_sk];
    if (scloud_kemkeygen(pk, sk)) return 1;
    const uint8_t *pke_pk = sk + scloudplus_pke_sk;  /* pk embedded in sk (re-enc) */

    /* extract the true secret column g* */
    static uint16_t S[(size_t)scloudplus_n * scloudplus_nbar];
    unpack_sk(sk, S);
    int gstar[scloudplus_nbar];
    for (unsigned j = 0; j < scloudplus_nbar; j++)
        gstar[j] = center(S[(size_t)j * scloudplus_n + 0]);
    fprintf(stderr, "true g* =");
    for (unsigned j = 0; j < scloudplus_nbar; j++) fprintf(stderr, " %+d", gstar[j]);
    fprintf(stderr, "\n");

    memo = calloc(MEMO_SLOTS, sizeof(*memo));   /* m -> profile cache */

    size_t total = 1; for (unsigned j = 0; j < scloudplus_nbar; j++) total *= 3;
    /* survivor masks for the two granularities */
    uint8_t *alive_b = malloc(total), *alive_r = malloc(total);
    memset(alive_b, 1, total); memset(alive_r, 1, total);
    size_t nb = total, nr = total;

    uint8_t baseline[scloudplus_ss] = {0};
    uint16_t c2base[(size_t)scloudplus_mbar * scloudplus_nbar];
    msg_encode(baseline, c2base);

    /* candidate cache: bucket each surviving code produces under a trial probe.
     * Used by adaptive mode to pick a probe that best splits current survivors. */
    const int adaptive = argc > 3 ? (int)strtoul(argv[3], 0, 10) : 0;
    const unsigned trials = argc > 4 ? (unsigned)strtoul(argv[4], 0, 10) : 64U;
    /* argv[6] = stall limit (0 disables early stop; rare-event regime needs a
     * large value or 0, since informative probes arrive ~1.13% of the time) */
    const size_t stall_arg = argc > 6 ? (size_t)strtoull(argv[6], 0, 10) : 20;

    printf("probe,alpha,offset,obs_bucket,obs_rounds,alive_bucket,alive_rounds\n");
    unsigned mismatches = 0;
    size_t last_nb = nb, last_nr = nr, stall = 0;
    const size_t stall_limit = stall_arg;   /* 0 disables early stop */
    for (unsigned t = 0; t < nprobes; t++) {
        unsigned alpha, offset;
        if (!adaptive) {
            /* random non-degenerate probe: alpha avoids {0,512}; offset arbitrary */
            alpha = 0; while (alpha == 0 || alpha == 512) alpha = (unsigned)(xr() & scloudplus_q_mask);
            offset = (unsigned)(xr() & scloudplus_q_mask);
        } else {
            /* ADAPTIVE: among `trials` random probes, pick the one that splits the
             * current bucket-survivors most evenly (max partition entropy). This
             * targets the surviving equivalence class rather than the global set. */
            double best_score = -1.0; alpha = 1; offset = 0;
            for (unsigned tr = 0; tr < trials; tr++) {
                unsigned aa = 0; while (aa == 0 || aa == 512) aa = (unsigned)(xr() & scloudplus_q_mask);
                unsigned oo = (unsigned)(xr() & scloudplus_q_mask);
                /* score = entropy of the bucket-partition over a random SUBSET of
                 * current survivors (relative comparison only needs an estimate). */
                size_t hist[64] = {0}, drawn = 0;
                uint16_t d[(size_t)scloudplus_mbar * scloudplus_nbar];
                uint8_t m[scloudplus_ss];
                uint16_t c2t[(size_t)scloudplus_mbar * scloudplus_nbar];
                memcpy(c2t, c2base, sizeof(c2t));
                c2t[0] = (uint16_t)((c2t[0] + oo) & scloudplus_q_mask);
                const size_t want = nb < 256 ? nb : 256;   /* subset size */
                for (uint32_t code = 0; code < total && drawn < want; code++) {
                    if (!alive_b[code]) continue;
                    /* thin to ~want samples across the alive set */
                    if (nb > want && (xr() % nb) >= want) continue;
                    uint32_t u = code; memcpy(d, c2t, sizeof(d));
                    for (unsigned j = 0; j < scloudplus_nbar; j++) {
                        int g = (int)(u % 3U) - 1; u /= 3U;
                        d[j] = (uint16_t)(d[j] - (uint32_t)aa * (uint32_t)(int32_t)g);
                    }
                    msg_decode(d, m);
                    size_t pb, pr; profile_message(pke_pk, m, &pb, &pr);
                    if (pb < 64) { hist[pb]++; drawn++; }
                }
                double H = 0.0; if (drawn) for (unsigned b = 0; b < 64; b++) if (hist[b]) {
                    double p = (double)hist[b] / (double)drawn; H -= p * log(p);
                }
                if (H > best_score) { best_score = H; alpha = aa; offset = oo; }
            }
        }

        uint16_t c2[(size_t)scloudplus_mbar * scloudplus_nbar];
        memcpy(c2, c2base, sizeof(c2));
        c2[0] = (uint16_t)((c2[0] + offset) & scloudplus_q_mask);

        /* real oracle: build ct=(C1,C2), decrypt with sk, sample -> observed */
        uint8_t ct[scloudplus_ctx]; uint8_t mreal[scloudplus_ss];
        uint16_t c1[(size_t)scloudplus_mbar * scloudplus_n];
        memset(c1, 0, sizeof(c1));
        c1[0] = (uint16_t)(alpha & scloudplus_q_mask);
        pack_c1(c1, ct);
        pack_c2(c2, ct + scloudplus_c1);
        pke_dec(sk, ct, mreal);
        size_t obs_b, obs_r; profile_message(pke_pk, mreal, &obs_b, &obs_r);
        /* Run the complete KEM decapsulation as the actual oracle path too.
         * The sampler.c included in this translation unit instruments every
         * SHAKE refill used by pke_enc inside scloud_kemdecaps.  The decoded
         * message/profile above is the offline prediction; this check makes
         * sure the complete FO path produces the same refill bucket. */
        uint8_t ss_check[scloudplus_ss];
        generated_bytes = 0;
        if (scloud_kemdecaps(sk, ct, ss_check) != 0) return 3;
        const size_t kem_b = generated_bytes / 544;
        if (kem_b != obs_b) {
            fprintf(stderr, "KEM sampler bucket mismatch at probe %u: profile=%zu kem=%zu\n",
                    t, obs_b, kem_b);
            return 4;
        }

        /* offline prediction for every still-alive candidate */
        uint16_t d[(size_t)scloudplus_mbar * scloudplus_nbar];
        uint8_t m[scloudplus_ss];
        size_t self_b = 0, self_r = 0;   /* prediction at g == g* (consistency) */
        for (uint32_t code = 0; code < total; code++) {
            if (!alive_b[code] && !alive_r[code]) continue;
            uint32_t u = code; int is_star = 1;
            memcpy(d, c2, sizeof(d));
            for (unsigned j = 0; j < scloudplus_nbar; j++) {
                int g = (int)(u % 3U) - 1; u /= 3U;
                if (g != gstar[j]) is_star = 0;
                d[j] = (uint16_t)(d[j] - (uint32_t)alpha * (uint32_t)(int32_t)g);
            }
            msg_decode(d, m);
            size_t pb, pr; profile_message(pke_pk, m, &pb, &pr);
            if (is_star) { self_b = pb; self_r = pr; }
            if (alive_b[code] && pb != obs_b) { alive_b[code] = 0; nb--; }
            if (alive_r[code] && pr != obs_r) { alive_r[code] = 0; nr--; }
        }
        /* consistency: offline prediction at g* must equal the real oracle */
        if (self_b != obs_b || self_r != obs_r) mismatches++;

        printf("%u,%u,%u,%zu,%zu,%zu,%zu\n", t, alpha, offset, obs_b, obs_r, nb, nr);
        fflush(stdout);
        if (nb == 1 && nr == 1) break;
        /* plateau detection: neither granularity shrank this probe */
        if (stall_limit && nb == last_nb && nr == last_nr) {
            if (++stall >= stall_limit) {
                fprintf(stderr, "PLATEAU: %zu probes with no elimination "
                        "(bucket=%zu rounds=%zu) -> equivalence class reached\n",
                        stall, nb, nr);
                break;
            }
        } else stall = 0;
        last_nb = nb; last_nr = nr;
    }
    fprintf(stderr, "memo: %zu hits, %zu misses (%.1f%% distinct messages)\n",
            memo_hits, memo_miss,
            100.0 * memo_miss / (double)(memo_hits + memo_miss ? memo_hits + memo_miss : 1));
    fprintf(stderr, "consistency mismatches=%u (must be 0)\n", mismatches);
    fprintf(stderr, "final: alive_bucket=%zu alive_rounds=%zu of %zu\n", nb, nr, total);
    /* is g* uniquely pinned under each oracle? */
    fprintf(stderr, "bucket oracle %s g*; rounds oracle %s g*\n",
            nb == 1 ? "UNIQUELY recovers" : "does NOT isolate",
            nr == 1 ? "UNIQUELY recovers" : "does NOT isolate");
    free(alive_b); free(alive_r);
    return 0;
}
