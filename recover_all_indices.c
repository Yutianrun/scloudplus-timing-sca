/* Full two-probe validation for all first-row secret-column indices.
 * Each probe is sent through the real KEM decapsulation; the observed
 * generated-byte bucket is compared with the three offline predictions.
 */
#define main recover_demo_unused_main
#include "recover_demo.c"
#undef main

typedef struct { unsigned a; int delta; uint16_t v[scloudplus_nbar]; } probe_def;

static const unsigned aval[scloudplus_nbar] =
    {1,8,1,4,2,1,16,4,1,2,4};
static const int dval[scloudplus_nbar] =
    {-1,+1,-1,+1,-1,+1,-1,+1,+1,+1,-1};
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

static void decode_index(const uint16_t *v, unsigned target, unsigned a,
                         int s, uint8_t *mu)
{
    uint16_t d[(size_t)scloudplus_mbar * scloudplus_nbar] = {0};
    for (unsigned j=0; j<scloudplus_nbar; j++) {
        int g = (j == target) ? s : 0;
        d[j] = (uint16_t)((int)v[j] - (int)a*g) & scloudplus_q_mask;
    }
    msg_decode(d, mu);
}

static size_t real_bucket(const uint8_t *sk, const uint16_t *v,
                          unsigned c1_col, unsigned a, uint8_t *decoded)
{
    uint16_t c1[(size_t)scloudplus_mbar * scloudplus_n] = {0};
    uint16_t c2[(size_t)scloudplus_mbar * scloudplus_nbar] = {0};
    uint8_t ct[scloudplus_ctx], ss[scloudplus_ss];
    c1[c1_col] = (uint16_t)a;
    memcpy(c2, v, sizeof(v[0]) * scloudplus_nbar);
    pack_c1(c1, ct); pack_c2(c2, ct + scloudplus_c1);
    pke_dec(sk, ct, decoded);
    generated_bytes = 0;
    if (scloud_kemdecaps(sk, ct, ss) != 0) exit(3);
    return generated_bytes / 544;
}

int main(int argc, char **argv)
{
    /* argv[1] = key seed (via krng, which drives randombytes in recover_demo.c);
     * argv[2] = positions per coordinate to check (default: all scloudplus_n).
     * Lets us confirm the probe geometry is KEY-INDEPENDENT: rows[] are multiples
     * of the message scale (64), so a*trit (|.|<=16<32) never crosses a decode
     * cell boundary at non-target coords -- robust for ANY key. Bucket labels are
     * recomputed per key via profile_message(pke_pk,...). */
    if (argc > 1) krng = strtoull(argv[1], 0, 10) | 1ULL;
    unsigned per_coord = argc > 2 ? (unsigned)strtoul(argv[2], 0, 10) : scloudplus_n;
    unsigned kstep = scloudplus_n / per_coord; if (!kstep) kstep = 1;
    uint8_t pk[scloudplus_pk], sk[scloudplus_kem_sk];
    if (scloud_kemkeygen(pk, sk)) return 1;
    const uint8_t *pke_pk = sk + scloudplus_pke_sk;
    uint16_t S[(size_t)scloudplus_n * scloudplus_nbar];
    unpack_sk(sk, S);
    memo = calloc(MEMO_SLOTS, sizeof(*memo));
    if (!memo) return 1;
    puts("column,index,true,guess,base_obs,shift_obs,base_preds(-1,0,1),shift_preds(-1,0,1),pass");
    int all_pass = 1;
    size_t checked = 0;
    for (unsigned k=0; k<scloudplus_n; k+=kstep) {
      for (unsigned i=0; i<scloudplus_nbar; i++) {
        probe_def p = { aval[i], dval[i], {0} };
        memcpy(p.v, rows[i], sizeof(p.v));
        uint16_t shifted[scloudplus_nbar];
        memcpy(shifted, p.v, sizeof(shifted));
        shifted[i] = (uint16_t)((shifted[i] + p.delta + scloudplus_q) & scloudplus_q_mask);
        uint8_t m0[scloudplus_ss], m1[scloudplus_ss];
        size_t ob0 = real_bucket(sk, p.v, k, p.a, m0);
        size_t ob1 = real_bucket(sk, shifted, k, p.a, m1);
        size_t pb0[3], pb1[3];
        for (int s=-1; s<=1; s++) {
            uint8_t cm[scloudplus_ss];
            decode_index(p.v, i, p.a, s, cm);
            profile_message(pke_pk, cm, &pb0[s+1], &(size_t){0});
            decode_index(shifted, i, p.a, s, cm);
            profile_message(pke_pk, cm, &pb1[s+1], &(size_t){0});
        }
        int guess = 99;
        for (int s=-1; s<=1; s++)
            if (pb0[s+1] == ob0 && pb1[s+1] == ob1) guess = s;
        int true_value = center(S[(size_t)i*scloudplus_n + k]);
        int pass = guess == true_value && ob0 == pb0[true_value+1] &&
                   ob1 == pb1[true_value+1];
        all_pass &= pass;
        checked++;
        printf("%u,%u,%d,%d,%zu,%zu,%zu:%zu:%zu,%zu:%zu:%zu,%s\n", k, i,
               true_value, guess, ob0, ob1, pb0[0], pb0[1], pb0[2],
               pb1[0], pb1[1], pb1[2], pass ? "PASS" : "FAIL");
      }
    }
    fprintf(stderr, "full KEM two-probe matrix recovery: %s (%zu/%zu entries)\n",
            all_pass ? "PASS" : "FAIL", checked,
            (size_t)scloudplus_n * scloudplus_nbar);
    free(memo);
    return all_pass ? 0 : 2;
}
