/* Diagnostic: is there a C1-dependent timing offset unrelated to sampler bucket?
 * Compare (A) two C1=0 refs of same bucket 53  -> expect median diff ~0
 *         (B) a C1[0,0]=1 probe of bucket 53 vs C1=0 ref bucket 53
 *             -> if offset exists, median diff ~ +gap (a full 544 step), NOT 0.
 */
#define main recover_demo_unused_main
#include "recover_demo.c"
#undef main
#include <time.h>

static uint64_t mono_ns(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t);
    return (uint64_t)t.tv_sec*1000000000ULL+(uint64_t)t.tv_nsec; }
static volatile uint8_t sink;
static double td(const uint8_t*sk,const uint8_t*ct){ uint8_t ss[scloudplus_ss];
    uint64_t a=mono_ns(); scloud_kemdecaps(sk,ct,ss); uint64_t b=mono_ns();
    sink^=ss[0]; return (double)(b-a); }
static int cmpd(const void*a,const void*b){ double x=*(const double*)a,y=*(const double*)b; return (x>y)-(x<y);}
static double med(double*x,unsigned n){ qsort(x,n,sizeof(double),cmpd);
    return n&1?x[n/2]:0.5*(x[n/2-1]+x[n/2]); }

int main(int argc,char**argv){
    unsigned N=argc>1?(unsigned)strtoul(argv[1],0,10):3000;
    if(argc>2) krng=strtoull(argv[2],0,10)|1ULL;
    uint8_t pk[scloudplus_pk],sk[scloudplus_kem_sk];
    if(scloud_kemkeygen(pk,sk))return 1;
    const uint8_t*pke_pk=sk+scloudplus_pke_sk;
    memo=calloc(MEMO_SLOTS,sizeof(*memo));

    /* two distinct C1=0 messages both bucket 53, and find a C1[0,0]=1 probe
       (vary C2[0,0]) whose DECODED message has bucket 53. */
    uint8_t a53[scloudplus_ss]={0}, b53[scloudplus_ss]={0};
    int na=0,nb=0;
    for(unsigned c=0;c<200000 && !(na&&nb);c++){
        uint8_t m[scloudplus_ss]={0};
        for(unsigned j=0;j<8;j++) m[j]=(uint8_t)(c>>(8*j));
        size_t bu,r; profile_message(pke_pk,m,&bu,&r);
        if(bu==53){ if(!na){memcpy(a53,m,sizeof(m));na=1;}
                    else if(!nb){memcpy(b53,m,sizeof(m));nb=1;} }
    }
    uint16_t S[(size_t)scloudplus_n*scloudplus_nbar]; unpack_sk(sk,S);

    uint8_t ctA[scloudplus_ctx],ctB[scloudplus_ctx];
    { uint16_t c1[(size_t)scloudplus_mbar*scloudplus_n]={0};
      uint16_t c2[(size_t)scloudplus_mbar*scloudplus_nbar];
      msg_encode(a53,c2); pack_c1(c1,ctA); pack_c2(c2,ctA+scloudplus_c1);
      msg_encode(b53,c2); pack_c1(c1,ctB); pack_c2(c2,ctB+scloudplus_c1); }

    /* build a C1[0,0]=1 probe whose decoded bucket is 53: randomize full C2
       first row until the decoded message lands in bucket 53. */
    uint8_t ctP[scloudplus_ctx]; int foundP=0; size_t pbucket=0;
    for(unsigned tries=0; tries<2000000 && !foundP; tries++){
        uint16_t c1[(size_t)scloudplus_mbar*scloudplus_n]={0};
        uint16_t c2[(size_t)scloudplus_mbar*scloudplus_nbar]={0};
        c1[0]=1;
        for(unsigned j=0;j<scloudplus_nbar;j++)
            c2[j]=(uint16_t)(xr() & scloudplus_q_mask);
        uint8_t ct[scloudplus_ctx], mdec[scloudplus_ss];
        pack_c1(c1,ct); pack_c2(c2,ct+scloudplus_c1);
        pke_dec(sk,ct,mdec);
        size_t bu,r; profile_message(pke_pk,mdec,&bu,&r);
        if(bu==53){ memcpy(ctP,ct,sizeof(ct)); foundP=1; pbucket=bu; }
    }
    if(!na||!nb||!foundP){ fprintf(stderr,"setup fail na=%d nb=%d P=%d\n",na,nb,foundP); return 2;}

    for(unsigned i=0;i<300;i++){(void)td(sk,ctA);(void)td(sk,ctB);(void)td(sk,ctP);}
    double *dAB=malloc(sizeof(double)*N),*dPA=malloc(sizeof(double)*N);
    for(unsigned i=0;i<N;i++){
        double x,y;
        if(xr()&1){x=td(sk,ctB);y=td(sk,ctA);} else {y=td(sk,ctA);x=td(sk,ctB);}
        dAB[i]=x-y;
        if(xr()&1){x=td(sk,ctP);y=td(sk,ctA);} else {y=td(sk,ctA);x=td(sk,ctP);}
        dPA[i]=x-y;
    }
    fprintf(stderr,"ctrl (C1=0 bkt53 vs C1=0 bkt53): median diff = %.1f ns  [expect ~0]\n",med(dAB,N));
    fprintf(stderr,"test (C1[0,0]=1 bkt53 vs C1=0 bkt53): median diff = %.1f ns  [bucket same => expect ~0; if ~+gap, C1 offset confirmed]\n",med(dPA,N));
    free(dAB);free(dPA);free(memo);
    return 0;
}
