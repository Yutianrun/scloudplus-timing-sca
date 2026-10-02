/* Key-free audit: is the hardcoded rows[] probe table decode-robust UNIVERSALLY?
 *
 * The two-probe decoder in recover_all_indices.c predicts the decoded message
 * assuming non-target coordinates contribute ZERO perturbation, while the real
 * decryption subtracts a*S[k,j] at EVERY coordinate j. The prediction is valid
 * for ANY key iff msg_decode(v) is invariant under adding any delta in
 * {-a..+a} at every non-target coordinate j != i (since a*trit ranges there).
 *
 * msg_decode does NOT use the key, so this robustness is a KEY-INDEPENDENT
 * geometric fact. We audit, per coordinate i, how many (j, delta) perturbations
 * flip the decoded message for base row v and shifted row vs. Zero flips => the
 * hardcoded table is a legitimate pk-only probe (works for all keys). Any flips
 * => default-key success is secret-specific luck, not a universal attack.
 */
#define main recover_demo_unused_main
#include "recover_demo.c"
#undef main

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

static int flips(const uint16_t *v, unsigned i, unsigned a)
{
    /* zero-init: C2 only occupies the first row (nbar entries); the remaining
     * (mbar-1)*nbar entries of the decode matrix are zero in the real probe. */
    uint16_t d[(size_t)scloudplus_mbar * scloudplus_nbar] = {0};
    uint8_t m0[scloudplus_ss], mt[scloudplus_ss];
    memcpy(d, v, sizeof(uint16_t) * scloudplus_nbar);
    msg_decode(d, m0);
    int bad = 0;
    for (unsigned j = 0; j < scloudplus_nbar; j++) {
        if (j == i) continue;
        for (int t = -(int)a; t <= (int)a; t += (int)a) {   /* only -a, 0, +a occur */
            uint16_t d2[(size_t)scloudplus_mbar * scloudplus_nbar] = {0};
            memcpy(d2, v, sizeof(uint16_t) * scloudplus_nbar);
            d2[j] = (uint16_t)((int)v[j] - t) & scloudplus_q_mask;  /* real subtracts a*S */
            msg_decode(d2, mt);
            if (memcmp(m0, mt, scloudplus_ss) != 0) bad++;
        }
    }
    return bad;
}

int main(void)
{
    memo = NULL;
    unsigned total_bad = 0;
    for (unsigned i = 0; i < scloudplus_nbar; i++) {
        uint16_t vs[scloudplus_nbar];
        memcpy(vs, rows[i], sizeof(vs));
        vs[i] = (uint16_t)((vs[i] + dval[i] + scloudplus_q) & scloudplus_q_mask);
        int fb = flips(rows[i], i, aval[i]);
        int fs = flips(vs,      i, aval[i]);
        printf("coord %2u a=%2u: base flips=%d shift flips=%d\n", i, aval[i], fb, fs);
        total_bad += fb + fs;
    }
    printf("TOTAL non-robust (message-flipping) perturbations: %u\n", total_bad);
    printf("%s\n", total_bad == 0
        ? "=> table is UNIVERSALLY robust (valid pk-only probe for any key)"
        : "=> table is NOT universally robust (default-key success is secret-specific)");
    return 0;
}
