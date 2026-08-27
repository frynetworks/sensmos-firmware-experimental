#!/usr/bin/env bash
# Flash a PlatformIO env to the ESP8266, retrying past FryStation's intermittent COM12 lock
# (an unknown periodic holder frees the port ~1/3 of a ~6s cycle; pio upload has no retry).
# Resolves the port dynamically by VID:PID each attempt (survives FTDI re-enumeration).
# Usage: tools/flash.sh <env>   (default env: nodemcuv2)
set -u
ENVNAME="${1:-nodemcuv2}"
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(dirname "$here")"
cd "$repo" || exit 2
for i in $(seq 1 15); do
  port="$(py -3 -c "import sys;sys.path.insert(0,'tools');import _serialutil as s;print(s.resolve_port(verbose=False))" 2>/dev/null)"
  if [ -z "$port" ]; then echo "attempt $i: no FTDI port resolved; wait"; sleep 4; continue; fi
  echo "=== flash attempt $i env=$ENVNAME port=$port ==="
  if pio run -e "$ENVNAME" -t upload --upload-port "$port"; then
    echo "FLASH_OK attempt=$i port=$port"
    exit 0
  fi
  echo "attempt $i failed; retry in 4s"
  sleep 4
done
echo "FLASH_FAILED after 15 attempts"
exit 1
