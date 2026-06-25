# vhs tape — records the SovereignSec-AI ablation (Semgrep-CE-only -> +cross-file taint).
# Render:  vhs demo/recording/ablation.tape   (needs vhs + ffmpeg + ttyd)
# Output:  demo/recording/ablation.gif

Output demo/recording/ablation.gif
Set FontSize 18
Set Width 1200
Set Height 760
Set Theme "Dracula"
Set Padding 16

Type "# SovereignSec-AI — local, air-gapped code-security auditor"
Enter
Sleep 800ms
Type "# Ablation on a seeded cross-file SQLi (Semgrep CE can't follow it)"
Enter
Sleep 1s
Type 'PATH="$PWD/.venv/bin:$PATH" PYTHONPATH=. .venv/bin/python demo/run_ablation.py'
Enter
Sleep 6s
Type "# Semgrep-CE-only R=0.5 (misses it) -> +L1 cross-file taint P=R=1.0, no FP"
Enter
Sleep 3s
