#!/bin/sh
# Static CPU backends must not inherit either the compiler host or an old cache's ISA.
# Keep ggml's existing runtime checks/tinyBLAS enabled; no GPU or dynamic modules.
set -eu
case "${1:?usage: speech-cpu-policy.sh TARGET}" in
  x86_64-unknown-linux-gnu|x86_64-unknown-linux-musl)
    printf '%s\n' '-DTRANSCRIBE_X86_CONSERVATIVE=ON -DGGML_NATIVE=OFF -DGGML_SSE42=OFF -DGGML_AVX=OFF -DGGML_AVX_VNNI=OFF -DGGML_AVX2=OFF -DGGML_BMI2=OFF -DGGML_FMA=OFF -DGGML_F16C=OFF -DGGML_AVX512=OFF -DGGML_AVX512_VBMI=OFF -DGGML_AVX512_VNNI=OFF -DGGML_AVX512_BF16=OFF -DGGML_AMX_TILE=OFF -DGGML_AMX_INT8=OFF -DGGML_AMX_BF16=OFF'
    ;;
  aarch64-unknown-linux-musl)
    printf '%s\n' '-DGGML_NATIVE=OFF -DGGML_CPU_ARM_ARCH=armv8-a'
    ;;
  *) echo 'Unsupported speech CPU target' >&2; exit 2 ;;
esac
