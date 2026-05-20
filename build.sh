#!/bin/sh
set -eu

PROJECT=ttun
OUT=build

rm -rf "$OUT"
mkdir -p "$OUT"

PLATFORMS=$(go tool dist list)
FAILED=""

for PLATFORM in $PLATFORMS; do
  GOOS=$(echo "$PLATFORM" | cut -d'/' -f1)
  GOARCH=$(echo "$PLATFORM" | cut -d'/' -f2)
  case "$GOOS" in
    darwin|linux|windows) ;;
    *) continue ;;
  esac

  NAME="${PROJECT}_${GOOS}_${GOARCH}"
  if [ "$GOOS" = "windows" ]; then
    NAME="${NAME}.exe"
  fi

  EXTRA=""
  case "$GOARCH" in
    mips|mipsle|mips64|mips64le) EXTRA="GOMIPS=softfloat" ;;
  esac

  echo "build $NAME"
  if ! env CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" $EXTRA \
      go build -trimpath -ldflags "-s -w" \
      -o "$OUT/$NAME" .; then
    echo "  -> failed: $NAME"
    FAILED="$FAILED $NAME"
  fi
done

if [ -n "$FAILED" ]; then
  echo
  echo "FAILED builds:$FAILED"
  exit 1
fi
