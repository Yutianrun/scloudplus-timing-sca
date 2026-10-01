#!/usr/bin/env python3
"""Empirical error-rate curve + variance scaling for the 53/54 timing classifier.

Falsification targets:
  (A) Does the trimmed-mean differential estimator's spread fall as N^{-1/2}?
      A shallower exponent => residual drift => the eps projection is optimistic.
  (B) Empirical classification error eps(N) vs the Gaussian projection.
"""
import csv, sys, math, random, statistics as st

path = sys.argv[1] if len(sys.argv) > 1 else 'timing-eps.csv'
R = list(csv.DictReader(open(path)))
lo = [float(r['low_ns']) for r in R]
hi = [float(r['high_ns']) for r in R]
d = [h - l for l, h in zip(lo, hi)]
n = len(d)
print(f"loaded {n} paired samples from {path}")


def trimmed_mean(x, a=0.1):
    s = sorted(x); k = int(a * len(s)); return st.mean(s[k:len(s) - k])


# --- (A) variance scaling: SD of trimmed-mean estimate vs chunk size N ---
print("\n(A) spread of trimmed-mean differential vs chunk size (bootstrap, B=600):")
print(f"{'N':>7} {'est_mean':>10} {'SD_est':>10} {'SD*sqrt(N)':>12}")
Ns = [n // k for k in (30, 20, 10, 6, 4, 2) if n // k >= 200]
prev = None
scaling = []
for N in Ns:
    ests = []
    for _ in range(600):
        chunk = [d[random.randrange(n)] for _ in range(N)]
        ests.append(trimmed_mean(chunk))
    sd = st.pstdev(ests); m = st.mean(ests)
    print(f"{N:>7} {m:>+10.1f} {sd:>10.1f} {sd*math.sqrt(N):>12.0f}")
    scaling.append((N, sd))
# fit log-log slope: SD ~ N^beta ; white noise => beta=-0.5
xs = [math.log(N) for N, _ in scaling]; ys = [math.log(sd) for _, sd in scaling]
mx, my = st.mean(xs), st.mean(ys)
beta = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sum((x - mx) ** 2 for x in xs)
print(f"\n  fitted scaling exponent beta = {beta:.3f}  (white noise: -0.500;"
      f" >-0.5 i.e. closer to 0 => drift-limited, projection too optimistic)")

# --- (B) empirical sign-error rate of the classifier vs N ---
print("\n(B) empirical classifier error eps(N) = P(trimmed-mean differential <= 0):")
print(f"{'N':>7} {'eps_emp':>10} {'eps_gauss':>10}")
sig = trimmed_mean(d)  # best estimate of true signal
sigma1 = st.pstdev(d)  # per-sample spread (upper bound; mean-based)


def phi(z):
    return 0.5 * (1 + math.erf(z / math.sqrt(2)))


for N in Ns:
    wrong = 0; B = 1500
    for _ in range(B):
        chunk = [d[random.randrange(n)] for _ in range(N)]
        if trimmed_mean(chunk) <= 0:
            wrong += 1
    eps_emp = wrong / B
    eps_g = phi(-sig * math.sqrt(N) / sigma1)
    print(f"{N:>7} {eps_emp:>10.4f} {eps_g:>10.4f}")
print("\n  if eps_emp tracks eps_gauss down, the projection holds;"
      "\n  if eps_emp plateaus above it, drift floor caps the channel.")
