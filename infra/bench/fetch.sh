# shellcheck shell=bash
bench_fetch() {
  while [ $# -gt 0 ]; do
    case "$1" in
      -h|--help)
        echo "Usage: ./bench fetch"
        echo ""
        echo "Verifies that AOSP image artifacts are present in infra/arm/."
        echo "If missing, prints instructions for downloading."
        return 0
        ;;
      *) shift ;;
    esac
  done

  local ok=1
  if ! ls infra/arm/aosp_cf_arm64_phone-img-*.zip >/dev/null 2>&1; then
    echo "ERROR: no arm64 AOSP zip in infra/arm/." >&2
    echo "  Download from https://ci.android.com/builds/branches/aosp-android13-gsi/grid?legacy=1" >&2
    echo "  Target: aosp_cf_arm64_phone, artifact: aosp_cf_arm64_phone-img-<BUILD>.zip" >&2
    ok=0
  fi
  if ! ls infra/arm/cvd-host_package.tar.gz >/dev/null 2>&1; then
    echo "ERROR: no cvd-host_package.tar.gz in infra/arm/." >&2
    ok=0
  fi

  if [ "$ok" = 0 ]; then
    return 1
  fi
  echo "  artifacts present in infra/arm/"
}
