#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

IMPL="latest-download/Implementations and Test_Vectors/Implementations"
CORE="$IMPL/_shared/scloudplus_core"
BIN=recover-e2e-par

echo "=== Building $BIN ==="
gcc -O2 -std=c99 \
  -DSCLOUDPLUS_FAMILY_AES \
  -DSCLOUDPLUS_TIER_REFERENCE \
  -DSCLOUDPLUS_REF_FAMILY_AES \
  -I"$IMPL/Reference_Implementation/Scloudplus-256/kem" \
  -I"$CORE/include" \
  -I"$CORE/common" \
  -I"$IMPL/_shared/api_pkc" \
  recover_e2e_par.c \
  "$CORE/common/encode.c" \
  "$CORE/common/hash_aes_shake.c" \
  "$CORE/common/kem.c" \
  "$CORE/common/pke.c" \
  "$CORE/common/util.c" \
  "$CORE/ref/matrix_reference.c" \
  "$CORE/ref/pack_reference.c" \
  "$CORE/ref/aes_reference.c" \
  -lm -o "$BIN"
echo "=== Build OK ==="

echo "=== Running parallel e2e recovery ===" >&2
./"$BIN" "$@"
