# Recording the demo

**Recording options:** there is no built-in screen recorder here, but there are three good
routes, and a Linux box can do all of them:

## 1. Reproducible TERMINAL clips — `vhs` (recommended for the portfolio)
[charmbracelet/vhs](https://github.com/charmbracelet/vhs) renders a `.tape` script to
MP4/GIF/WebM — deterministic and re-runnable (re-render after every code change, no
manual re-recording). A ready tape is in `ablation.tape`.
```bash
# install (Go) — needs ffmpeg + ttyd
go install github.com/charmbracelet/vhs@latest   # or: download a release binary
sudo apt-get install ffmpeg ttyd
vhs demo/recording/ablation.tape                  # -> ablation.gif / ablation.mp4
```
Alternative, zero-config: `asciinema rec run.cast` then `agg run.cast run.gif`.

## 2. Live split-screen (the money shot: scan + zero-egress + GPU)
For the "code never leaves the box" proof you want three panes recorded together:
the auditor scanning, a **network monitor showing zero egress**, and a **GPU monitor**.
- Tiled terminal (tmux) panes: `watch -n1 nvidia-smi` · `sudo nethogs`/`bandwhich` (egress) · the scan.
- Capture with **OBS Studio** (best for composed multi-pane) or `ffmpeg` x11grab (X11) /
  `wf-recorder` (Wayland):
  ```bash
  ffmpeg -f x11grab -framerate 30 -i :0.0 -c:v libx264 -pix_fmt yuv420p demo.mp4
  ```
- Zero-egress proof: run the scan under `firejail --net=none` and show `bandwhich` flat at 0.

## 3. Polished NARRATED explainer
A programmatic explainer video (HTML → MP4 cloud render) via a service like **HeyGen
HyperFrames**, with AI b-roll from a media-generation tool. Good for the marketing cut on a
portfolio site — not for capturing the live run (use #1/#2 for that).

## Suggested cut list
1. `vhs` clip of `demo/run_ablation.py` (Semgrep-CE R=0.5 → +Bandit recovers the sink R=1.0 → +taint traces the cross-file path).
2. `vhs` clip of the agent run emitting the cross-file SQLi finding.
3. OBS split-screen: full scan + `bandwhich` at 0 egress + `nvidia-smi`.
4. (optional) HyperFrames narrated intro/outro.
