#!/usr/bin/env bash
# Split-screen "money shot": the auditor scanning · GPU · zero-egress monitor.
# Reproducible render:   PATH="$PWD/.tmp/bin:$PATH" vhs demo/recording/splitscreen.tape
# Live capture (desktop): run this, then record the window in OBS / ffmpeg x11grab.
# No sudo needed — egress is read from /proc/net/dev (external iface TX bytes).
set -u
SESS=sscai_demo
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"; cd "$ROOT"
tmux kill-session -t "$SESS" 2>/dev/null
tmux new-session -d -s "$SESS" -x 210 -y 50

# pane 0 (left): the auditor scan — proves findings + "code never left the box"
tmux send-keys -t "$SESS":0.0 \
  'PATH="$PWD/.venv/bin:$PATH" PYTHONPATH=. .venv/bin/python demo/run_ablation.py; echo; echo ">> scan complete — fully local, zero egress"' C-m

# pane 1 (top-right): GPU
tmux split-window -h -t "$SESS":0
tmux send-keys -t "$SESS":0.1 \
  'for i in $(seq 1 18); do clear; echo "== GPU =="; nvidia-smi --query-gpu=utilization.gpu,memory.used,memory.total --format=csv,noheader,nounits | sed "s/^/util%, mem MiB: /"; sleep 1; done' C-m

# pane 2 (bottom-right): external egress (should stay ~0 during a local scan)
tmux split-window -v -t "$SESS":0.1
tmux send-keys -t "$SESS":0.2 \
  'IF=$(ip route 2>/dev/null | awk "/default/{print \$5; exit}"); IF=${IF:-eth0}; echo "== EGRESS ($IF) =="; prev=0; for i in $(seq 1 18); do tx=$(awk -v k="$IF:" "\$1==k{print \$10}" /proc/net/dev); d=$((tx-prev)); [ "$prev" -ne 0 ] && echo "external TX: ${d} B/s"; prev=$tx; sleep 1; done' C-m

tmux select-layout -t "$SESS":0 tiled
tmux attach -t "$SESS"
