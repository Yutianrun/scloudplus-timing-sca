/* Quantify timing-differential noise so improvements can be MEASURED, not claimed.
 *
 * Times two SAME-bucket (bucket 53) C1=0 ciphertexts, interleaved-paired. The
 * true differential is 0, so the paired-difference distribution's spread is pure
 * measurement noise. We report median (bias) and MAD (robust spread), plus the
 * median of |per-N-block aggregate| which bounds how large the real gap must be
 * to clear the noise. Lower MAD => fewer shots needed per bucket decision.
 *
 * Also optionally does an inner-repeat average (R back-to-back decaps per side
 * per shot) to test whether batching reduces per-shot variance.
 *
 * Args: [N] [inner_R] [clock] [key_seed]   clock: 0=MONOTONIC 1=MONOTONIC_RAW
 */
#define main recover_demo_unused_main
#include "recover_demo.c"
#undef main
#include <time.h>

static clockid_t CLK = CLOCK_MONOTONIC;
static uint64_t mono_ns(void){ struct timespec t; clock_gettime(CLK,&t);
    return (uint64_t)t.tv_sec*1000000000ULL+(uint64_t)t.tv_nsec; }
static volatile uint8_t sink;

/* time R back-to-back decaps of the same ct, return total ns */
static double td(const uint8_t*sk,const uint8_t*ct,unsigned R){
    uint8_t ss[scloudplus_ss]; uint64_t a=mono_ns();
    for(unsigned i=0;i<R;i++){ scloud_kemdecaps(sk,ct,ss); sink^=ss[0]; }
    return (double)(mono_ns()-a); }

static int cmpd(const void*a,const void*b){ double x=*(const double*)a,y=*(const double*)b; return (x>y)-(x<y);}
static double med(double*x,unsigned n){ qsort(x,n,sizeof(double),cmpd);
    return n&1?x[n/2]:0.5*(x[n/2-1]+x[n/2]); }
static double mad(double*x,unsigned n,double m){
    double*t=malloc(sizeof(double)*n);
    for(unsigned i=0;i<n;i++) t[i]=fabs(x[i]-m);
    double r=med(t,n); free(t); return 1.4826*r; }  /* ~sigma for gaussian */

int main(int argc,char**argv){
    unsigned N=argc>1?(unsigned)strtoul(argv[1],0,10):4000;
    unsigned R=argc>2?(unsigned)strtoul(argv[2],0,10):1;
    if(argc>3 && strtoul(argv[3],0,10)==1) CLK=CLOCK_MONOTONIC_RAW;
    if(argc>4) krng=strtoull(argv[4],0,10)|1ULL;
    uint8_t pk[scloudplus_pk],sk[scloudplus_kem_sk];
    if(scloud_kemkeygen(pk,sk))return 1;
    const uint8_t*pke_pk=sk+scloudplus_pke_sk;
    memo=calloc(MEMO_SLOTS,sizeof(*memo));

    /* two distinct C1=0 messages, both bucket 53 */
    uint8_t a53[scloudplus_ss]={0}, b53[scloudplus_ss]={0}; int na=0,nb=0;
    for(unsigned c=0;c<200000 && !(na&&nb);c++){
        uint8_t m[scloudplus_ss]={0};
        for(unsigned j=0;j<8;j++) m[j]=(uint8_t)(c>>(8*j));
        size_t bu,r; profile_message(pke_pk,m,&bu,&r);
        if(bu==53){ if(!na){memcpy(a53,m,sizeof(m));na=1;}
                    else if(!nb){memcpy(b53,m,sizeof(m));nb=1;} } }
    if(!na||!nb){fprintf(stderr,"need two bkt53 refs\n");return 2;}
    uint8_t ctA[scloudplus_ctx],ctB[scloudplus_ctx];
    uint16_t c1[(size_t)scloudplus_mbar*scloudplus_n]={0};
    uint16_t c2[(size_t)scloudplus_mbar*scloudplus_nbar];
    msg_encode(a53,c2); pack_c1(c1,ctA); pack_c2(c2,ctA+scloudplus_c1);
    msg_encode(b53,c2); pack_c1(c1,ctB); pack_c2(c2,ctB+scloudplus_c1);

    for(unsigned i=0;i<300;i++){(void)td(sk,ctA,R);(void)td(sk,ctB,R);}

    double*d=malloc(sizeof(double)*N);
    for(unsigned i=0;i<N;i++){
        double x,y;
        if(xr()&1){x=td(sk,ctB,R);y=td(sk,ctA,R);} else {y=td(sk,ctA,R);x=td(sk,ctB,R);}
        d[i]=(x-y)/R;   /* per-decaps-equivalent difference */
    }
    double m=med(d,N), s=mad(d,N,m);
    /* spread of the N-block median aggregate via contiguous sub-blocks */
    double onecall=0; for(unsigned i=0;i<N;i++) onecall+=d[i]; (void)onecall;
    fprintf(stderr,"clock=%s inner_R=%u N=%u : per-shot median_bias=%.1f ns  MAD(~sigma)=%.1f ns\n",
            CLK==CLOCK_MONOTONIC_RAW?"RAW":"MONOTONIC",R,N,m,s);
    /* how many shots to clear a gap of 544B-equiv (use measured ~2000ns) with
       median: sigma_median ~ 1.253*sigma/sqrt(N); need gap/2 > ~3 sigma_median */
    double gap=2000.0;
    double need = pow(3.0*1.253*s/(gap/2.0),2.0);
    fprintf(stderr,"  implied shots N for 3-sigma separation at gap=2000ns: ~%.0f\n",need);
    free(d);free(memo);return 0;
}
