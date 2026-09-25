#!/bin/bash
# Wrapper so netprobe.mjs can drive Safari: node tools/bench/netprobe.mjs safari tools/bench/safari_open.sh
# open -a returns immediately; keep the process alive until killed.
open -a Safari "$1"; trap 'osascript -e "tell application \"Safari\" to close (every tab whose URL contains \"127.0.0.1\")" >/dev/null 2>&1' TERM; while true; do sleep 1; done
