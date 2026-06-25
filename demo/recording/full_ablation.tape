# vhs tape — the complete rungs-0->5 ablation table (base vs fine-tuned 7B).
# Render:  PATH="$PWD/.tmp/bin:$PATH" vhs demo/recording/full_ablation.tape
Output demo/recording/full_ablation.gif
Set FontSize 16
Set Width 1320
Set Height 820
Set Theme "Dracula"
Set Padding 16

Type "# SovereignSec-AI — complete rungs 0->5 (base 7B vs fine-tuned 7B on real held-out CVEs)"
Enter
Sleep 800ms
Type "PYTHONPATH=. .venv/bin/python demo/run_full_ablation.py --mode merge"
Enter
Sleep 7s
