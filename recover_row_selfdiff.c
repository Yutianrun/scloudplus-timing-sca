/* Self-differential PHYSICAL recovery: base-probe vs shift-probe directly.
 *
 * Both probes share IDENTICAL C1 (C1[0,k]=a), so the C1*S matrix-mult cost
 * cancels exactly in the paired difference -- removing the C1-baseline
 * inconsistency that biased the self-reference classifier. No reference
 * ciphertext is needed.
 *
 * Signal: median(t_base - t_shift)
 *   base/shift land in DIFFERENT buckets  -> |median| ~ gap   (one 544B step)
 *   base/shift land in the SAME bucket     -> |median| ~ 0
 * Decision: |median| > gap/2  => "different buckets" else "same".
 *
 * This can only separate same-vs-different buckets, i.e. recover the SPARSITY
 * pattern (which coefficients are zero vs nonzero) under the probe design where
 * s=0 yields different buckets and s=+-1 yields equal buckets. It cannot sign
 * +1 vs -1 (both are same-bucket).
 *
 * Reports TWO separate accuracies:
 *   (1) CHANNEL: timed same/diff vs offline NOISELESS same/diff (pure signal)
 *   (2) SPARSITY: predicted zero/nonzero vs true trit (incl. probe-table fit)
 *
 * gap is calibrated once from two C1=0 refs of known bucket 53 and 54.
 * Args: [count] [N_per_probe] [coord] [N_cal] [key_seed]
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

static clockid_t CLK = CLOCK_MONOTONIC_RAW;
static uint64_t mono_ns(void){ struct timespec t; clock_gettime(CLK,&t);
    return (uint64_t)t.tv_sec*1000000000ULL+(uint64_t)t.tv_nsec; }
static volatile uint8_t sink;
static double td(const uint8_t*sk,const uint8_t*ct){ uint8_t ss[scloudplus_ss];
    uint64_t a=mono_ns(); scloud_kemdecaps(sk,ct,ss); uint64_t b=mono_ns();
    sink^=ss[0]; return (double)(b-a); }
static int cmpd(const void*a,const void*b){ double x=*(const double*)a,y=*(const double*)b; return (x>y)-(x<y);}
static double med(double*x,unsigned n){ qsort(x,n,sizeof(double),cmpd);
    return n&1?x[n/2]:0.5*(x[n/2-1]+x[n/2]); }

static void build_probe(const uint16_t *v, unsigned c1_col, unsigned a, uint8_t *ct){
    uint16_t c1[(size_t)scloudplus_mbar*scloudplus_n]={0};
    uint16_t c2[(size_t)scloudplus_mbar*scloudplus_nbar]={0};
    c1[c1_col]=(uint16_t)a; memcpy(c2,v,sizeof(v[0])*scloudplus_nbar);
    pack_c1(c1,ct); pack_c2(c2,ct+scloudplus_c1); }

static void build_ref(const uint8_t*m,uint8_t*ct){
    uint16_t c1[(size_t)scloudplus_mbar*scloudplus_n]={0};
    uint16_t c2[(size_t)scloudplus_mbar*scloudplus_nbar];
    msg_encode(m,c2); pack_c1(c1,ct); pack_c2(c2,ct+scloudplus_c1); }

static size_t pred_bucket(const uint8_t*pke_pk,const uint16_t*v,unsigned target,unsigned a,int s){
    uint16_t d[(size_t)scloudplus_mbar*scloudplus_nbar]={0}; uint8_t mu[scloudplus_ss];
    for(unsigned j=0;j<scloudplus_nbar;j++){ int g=(j==target)?s:0;
        d[j]=(uint16_t)((int)v[j]-(int)a*g)&scloudplus_q_mask; }
    msg_decode(d,mu); size_t b,r; profile_message(pke_pk,mu,&b,&r); return b; }

int main(int argc,char**argv){
    unsigned count=argc>1?(unsigned)strtoul(argv[1],0,10):30;
    unsigned N    =argc>2?(unsigned)strtoul(argv[2],0,10):600;
    unsigned coord=argc>3?(unsigned)strtoul(argv[3],0,10):0;
    unsigned Ncal =argc>4?(unsigned)strtoul(argv[4],0,10):3000;
    if(argc>5) krng=strtoull(argv[5],0,10)|1ULL;
    uint8_t pk[scloudplus_pk],sk[scloudplus_kem_sk];
    if(scloud_kemkeygen(pk,sk))return 1;
    const uint8_t*pke_pk=sk+scloudplus_pke_sk;
    uint16_t S[(size_t)scloudplus_n*scloudplus_nbar]; unpack_sk(sk,S);
    memo=calloc(MEMO_SLOTS,sizeof(*memo)); if(!memo)return 1;

    /* calibrate gap from two C1=0 refs, bucket 53 & 54 */
    uint8_t m_lo[scloudplus_ss]={0},m_hi[scloudplus_ss]={0}; int hl=0,hh=0;
    for(unsigned c=0;c<200000&&!(hl&&hh);c++){ uint8_t m[scloudplus_ss]={0};
        for(unsigned j=0;j<8;j++)m[j]=(uint8_t)(c>>(8*j));
        size_t b,r; profile_message(pke_pk,m,&b,&r);
        if(b==53&&!hl){memcpy(m_lo,m,sizeof(m));hl=1;}
        if(b==54&&!hh){memcpy(m_hi,m,sizeof(m));hh=1;} }
    if(!hl||!hh){fprintf(stderr,"no refs\n");return 2;}
    uint8_t ct_lo[scloudplus_ctx],ct_hi[scloudplus_ctx];
    build_ref(m_lo,ct_lo); build_ref(m_hi,ct_hi);
    for(unsigned i=0;i<300;i++){(void)td(sk,ct_lo);(void)td(sk,ct_hi);}
    double*cal=malloc(sizeof(double)*Ncal);
    for(unsigned i=0;i<Ncal;i++){ double a,b;
        if(xr()&1){a=td(sk,ct_hi);b=td(sk,ct_lo);}else{b=td(sk,ct_lo);a=td(sk,ct_hi);}
        cal[i]=a-b; }
    double gap=fabs(med(cal,Ncal)); double thr=gap/2.0; free(cal);
    fprintf(stderr,"calibrated gap=%.1f ns threshold=%.1f ns (Ncal=%u)\n",gap,thr,Ncal);

    double*d=malloc(sizeof(double)*N);
    printf("k,coord,true,offline_same,timed_same,abs_med_ns,channel_ok,pred_nonzero,sparsity_ok,coef_s\n");
    unsigned ch_ok=0, sp_ok=0, done=0, nz_true=0;
    uint64_t w0=mono_ns();
    for(unsigned k=0;k<count;k++){
        uint16_t v[scloudplus_nbar],vs[scloudplus_nbar];
        memcpy(v,rows[coord],sizeof(v)); memcpy(vs,v,sizeof(vs));
        vs[coord]=(uint16_t)((vs[coord]+dval[coord]+scloudplus_q)&scloudplus_q_mask);
        unsigned a=aval[coord];
        uint8_t ctb[scloudplus_ctx],cts[scloudplus_ctx];
        build_probe(v,k,a,ctb); build_probe(vs,k,a,cts);
        uint64_t c0=mono_ns();
        for(unsigned i=0;i<N;i++){ double x,y;
            if(xr()&1){x=td(sk,ctb);y=td(sk,cts);}else{y=td(sk,cts);x=td(sk,ctb);}
            d[i]=x-y; }
        double m=med(d,N); double am=fabs(m);
        double coef_s=(double)(mono_ns()-c0)/1e9;
        int timed_same = am<=thr;              /* same bucket => |median|~0 */
        int tv=center(S[(size_t)coord*scloudplus_n+k]);
        size_t pb=pred_bucket(pke_pk,v,coord,a,tv), ps=pred_bucket(pke_pk,vs,coord,a,tv);
        int offline_same = (pb==ps);
        int channel_ok = (timed_same==offline_same);
        int pred_nonzero = timed_same;         /* same bucket => nonzero (s=+-1) */
        int sparsity_ok = (pred_nonzero==(tv!=0));
        ch_ok+=channel_ok; sp_ok+=sparsity_ok; nz_true+=(tv!=0); done++;
        printf("%u,%u,%d,%d,%d,%.0f,%d,%d,%d,%.2f\n",k,coord,tv,offline_same,
               timed_same,am,channel_ok,pred_nonzero,sparsity_ok,coef_s);
        fflush(stdout);
    }
    double wall=(double)(mono_ns()-w0)/1e9;
    fprintf(stderr,"CHANNEL (timed vs noiseless same/diff): %u/%u = %.1f%%\n",ch_ok,done,100.0*ch_ok/done);
    fprintf(stderr,"SPARSITY (zero/nonzero): %u/%u = %.1f%%  [all-zero baseline %.1f%%]\n",
            sp_ok,done,100.0*sp_ok/done,100.0*(done-nz_true)/done);
    fprintf(stderr,"mean %.2f s/coef; row(1184)~=%.1f h; wall %.1f s\n",wall/done,(wall/done)*1184/3600.0,wall);
    free(d);free(memo); return 0;
}
