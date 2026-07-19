#!/usr/bin/env bash

# Run a developer pre-CI matrix locally with already-installed GHCs.
#
# The default matrix builds and tests the checkout with every GHC listed in the
# package's tested-with field, exercises asm on/off where supported, builds
# Haddock, and finally builds/tests a freshly unpacked source distribution.
# It deliberately never installs toolchains or runs `cabal update`. This is not
# the complete release gate: sanitizer, dedicated cancellation/concurrency,
# archive-hardening, native-symbol, and coexistence checks are separate work.

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "${script_dir}/.." && pwd)"
cabal_file="${repo_dir}/boringssl.cabal"
matrix_build_root="${repo_dir}/dist-newstyle/local-ci"

declare -a requested_ghcs=()
declare -a selected_ghcs=()
declare -a asm_modes=()
declare -a rts_capabilities=(1 2 4)

installed_only=0
run_haddock=1
run_sdist=1
sdist_only=0
dry_run=0
network_mode="--offline"
skipped_ghcs=0

usage() {
  sed -n 's/^# //p' <<'EOF'
# Usage: scripts/local-ci.sh [OPTIONS]
#
# Options:
#   --ghc VERSION       Test one GHC version; repeat for several versions.
#                       Defaults to every exact version in tested-with.
#   --installed-only    Skip missing GHCs and label the result PARTIAL.
#   --no-asm            Test only the portable no-assembly build.
#   --asm-only          Test only the assembly-enabled build.
#   --no-haddock        Skip Haddock generation.
#   --no-sdist          Skip the unpacked-source-distribution smoke check.
#   --sdist-only        Run only Cabal check and the unpacked-sdist check.
#   --allow-network     Let Cabal access configured repositories.
#   --dry-run           Print commands without executing them.
#   -h, --help          Show this help.
#
# Examples:
#   scripts/local-ci.sh --ghc 9.6.7 --no-sdist
#   scripts/local-ci.sh --ghc 9.6.7 --sdist-only
#   scripts/local-ci.sh --installed-only
#   scripts/local-ci.sh --dry-run
EOF
}

while (($# > 0)); do
  case "$1" in
    --ghc)
      if (($# < 2)); then
        echo "local-ci: --ghc requires a version" >&2
        exit 2
      fi
      requested_ghcs+=("$2")
      shift 2
      ;;
    --installed-only)
      installed_only=1
      shift
      ;;
    --no-asm)
      asm_modes=(off)
      shift
      ;;
    --asm-only)
      asm_modes=(on)
      shift
      ;;
    --no-haddock)
      run_haddock=0
      shift
      ;;
    --no-sdist)
      run_sdist=0
      shift
      ;;
    --sdist-only)
      sdist_only=1
      shift
      ;;
    --allow-network)
      network_mode=""
      shift
      ;;
    --dry-run)
      dry_run=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "local-ci: unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if ((sdist_only == 1 && run_sdist == 0)); then
  echo "local-ci: --sdist-only and --no-sdist cannot be combined" >&2
  exit 2
fi

if ((${#requested_ghcs[@]} == 0)); then
  while IFS= read -r ghc_version; do
    if [[ -n "${ghc_version}" ]]; then
      requested_ghcs+=("${ghc_version}")
    fi
  done < <(
    sed -n 's/^tested-with:[[:space:]]*//p' "${cabal_file}" \
      | tr ',' '\n' \
      | sed -E 's/.*==[[:space:]]*//; s/[[:space:]]//g'
  )
fi

if ((${#requested_ghcs[@]} == 0)); then
  echo "local-ci: could not read any exact GHC versions from ${cabal_file}" >&2
  exit 2
fi

if ((${#asm_modes[@]} == 0)); then
  case "$(uname -s)" in
    Darwin|Linux) asm_modes=(off on) ;;
    *)            asm_modes=(off) ;;
  esac
fi

print_command() {
  printf '+'
  printf ' %q' "$@"
  printf '\n'
}

run() {
  print_command "$@"
  if ((dry_run == 0)); then
    "$@"
  fi
}

find_ghc() {
  local ghc_version="$1"
  local ghc_path=""

  if command -v ghcup >/dev/null 2>&1; then
    ghc_path="$(ghcup whereis ghc "${ghc_version}" 2>/dev/null || true)"
  fi
  if [[ -z "${ghc_path}" ]] && command -v "ghc-${ghc_version}" >/dev/null 2>&1; then
    ghc_path="$(command -v "ghc-${ghc_version}")"
  fi
  if [[ -z "${ghc_path}" ]] && command -v ghc >/dev/null 2>&1; then
    if [[ "$(ghc --numeric-version 2>/dev/null || true)" == "${ghc_version}" ]]; then
      ghc_path="$(command -v ghc)"
    fi
  fi

  printf '%s' "${ghc_path}"
}

for ghc_version in "${requested_ghcs[@]}"; do
  if ((dry_run == 1)); then
    selected_ghcs+=("${ghc_version}|ghc-${ghc_version}")
    continue
  fi

  ghc_path="$(find_ghc "${ghc_version}")"
  if [[ -z "${ghc_path}" ]]; then
    if ((installed_only == 1)); then
      echo "local-ci: skipping missing GHC ${ghc_version}" >&2
      skipped_ghcs=$((skipped_ghcs + 1))
      continue
    fi
    echo "local-ci: GHC ${ghc_version} is not installed" >&2
    echo "local-ci: install it explicitly (for example, ghcup install ghc ${ghc_version})" >&2
    exit 1
  fi
  resolved_version="$("${ghc_path}" --numeric-version 2>/dev/null || true)"
  if [[ "${resolved_version}" != "${ghc_version}" ]]; then
    echo "local-ci: resolved ${ghc_path}, but it reports GHC ${resolved_version:-<unknown>} instead of ${ghc_version}" >&2
    exit 1
  fi
  selected_ghcs+=("${ghc_version}|${ghc_path}")
done

if ((${#selected_ghcs[@]} == 0)); then
  echo "local-ci: no requested GHC toolchains are installed" >&2
  exit 1
fi

cd "${repo_dir}"
run cabal check

if ((sdist_only == 0)); then
  for selected in "${selected_ghcs[@]}"; do
    ghc_version="${selected%%|*}"
    ghc_path="${selected#*|}"

    for asm_mode in "${asm_modes[@]}"; do
      build_dir="${matrix_build_root}/ghc-${ghc_version}/asm-${asm_mode}"
      if [[ "${asm_mode}" == on ]]; then
        asm_flag="-fasm"
      else
        asm_flag="-f-asm"
      fi

      echo "local-ci: checkout / GHC ${ghc_version} / asm ${asm_mode}"
      cabal_common=(
        "--with-compiler=${ghc_path}"
        "--builddir=${build_dir}"
        "${asm_flag}"
      )
      if [[ -n "${network_mode}" ]]; then
        cabal_common+=("${network_mode}")
      fi

      run cabal build all "${cabal_common[@]}" --enable-tests --enable-benchmarks
      for capabilities in "${rts_capabilities[@]}"; do
        run cabal test all "${cabal_common[@]}" \
          --enable-tests --test-show-details=direct \
          "--test-option=--num-threads=${capabilities}" \
          "--test-options=+RTS -N${capabilities} -RTS"
      done
      if ((run_haddock == 1)); then
        run cabal haddock all "${cabal_common[@]}"
      fi
    done
  done
fi

if ((run_sdist == 1)); then
  if ((dry_run == 1)); then
    print_command cabal sdist --output-directory '<temporary-directory>'
    print_command tar -xzf '<package.tar.gz>' -C '<temporary-directory>'
    for selected in "${selected_ghcs[@]}"; do
      sdist_ghc_version="${selected%%|*}"
      sdist_ghc_path="${selected#*|}"
      for asm_mode in "${asm_modes[@]}"; do
        if [[ "${asm_mode}" == on ]]; then
          asm_flag="-fasm"
        else
          asm_flag="-f-asm"
        fi
        dry_sdist_common=(
          "--with-compiler=${sdist_ghc_path}"
          "--builddir=<temporary-directory>/dist-newstyle/ghc-${sdist_ghc_version}/asm-${asm_mode}"
          "${asm_flag}"
        )
        if [[ -n "${network_mode}" ]]; then
          dry_sdist_common+=("${network_mode}")
        fi
        print_command cabal build all "${dry_sdist_common[@]}" \
          --enable-tests --enable-benchmarks
        for capabilities in "${rts_capabilities[@]}"; do
          print_command cabal test all "${dry_sdist_common[@]}" \
            --enable-tests --test-show-details=direct \
            "--test-option=--num-threads=${capabilities}" \
            "--test-options=+RTS -N${capabilities} -RTS"
        done
        if ((run_haddock == 1)); then
          print_command cabal haddock all "${dry_sdist_common[@]}"
        fi
      done
    done
  else
    sdist_tmp="$(mktemp -d "${TMPDIR:-/tmp}/boringssl-hs-local-ci.XXXXXX")"
    cleanup_sdist() {
      if [[ -n "${sdist_tmp:-}" && -d "${sdist_tmp}" ]]; then
        rm -rf -- "${sdist_tmp}"
      fi
    }
    trap cleanup_sdist EXIT

    run cabal sdist --output-directory "${sdist_tmp}"
    sdist_tar="$(find "${sdist_tmp}" -maxdepth 1 -type f -name 'boringssl-*.tar.gz' -print -quit)"
    if [[ -z "${sdist_tar}" ]]; then
      echo "local-ci: cabal sdist did not produce the expected tarball" >&2
      exit 1
    fi
    run tar -xzf "${sdist_tar}" -C "${sdist_tmp}"
    sdist_source="$(find "${sdist_tmp}" -mindepth 1 -maxdepth 1 -type d -name 'boringssl-*' -print -quit)"
    if [[ -z "${sdist_source}" ]]; then
      echo "local-ci: could not find the unpacked source distribution" >&2
      exit 1
    fi

    cd "${sdist_source}"
    for selected in "${selected_ghcs[@]}"; do
      sdist_ghc_version="${selected%%|*}"
      sdist_ghc_path="${selected#*|}"
      for asm_mode in "${asm_modes[@]}"; do
        if [[ "${asm_mode}" == on ]]; then
          asm_flag="-fasm"
        else
          asm_flag="-f-asm"
        fi
        echo "local-ci: unpacked sdist / GHC ${sdist_ghc_version} / asm ${asm_mode}"
        sdist_common=(
          "--with-compiler=${sdist_ghc_path}"
          "--builddir=${sdist_tmp}/dist-newstyle/ghc-${sdist_ghc_version}/asm-${asm_mode}"
          "${asm_flag}"
        )
        if [[ -n "${network_mode}" ]]; then
          sdist_common+=("${network_mode}")
        fi
        run cabal build all "${sdist_common[@]}" --enable-tests --enable-benchmarks
        for capabilities in "${rts_capabilities[@]}"; do
          run cabal test all "${sdist_common[@]}" \
            --enable-tests --test-show-details=direct \
            "--test-option=--num-threads=${capabilities}" \
            "--test-options=+RTS -N${capabilities} -RTS"
        done
        if ((run_haddock == 1)); then
          run cabal haddock all "${sdist_common[@]}"
        fi
      done
    done
    cd "${repo_dir}"
  fi
fi

if ((dry_run == 1)); then
  echo "local-ci: dry run complete; no build or test gate was executed"
elif ((skipped_ghcs > 0)); then
  echo "local-ci: PARTIAL developer matrix passed; skipped ${skipped_ghcs} missing GHC toolchain(s)"
else
  echo "local-ci: developer matrix passed"
fi
