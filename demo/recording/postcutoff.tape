# vhs tape — post-cutoff (leak-resistant) ablation: base 32B vs fine-tuned 32B.
# Render:  PATH="$PWD/.tmp/bin:$PATH" vhs demo/recording/postcutoff.tape
Output demo/recording/postcutoff.gif
Set FontSize 16
Set Width 1320
Set Height 720
Set Theme "Dracula"
Set Padding 16

Type "# Leak-resistant eval: real CVEs published 2025-2026, base 32B vs fine-tuned 32B"
Enter
Sleep 700ms
Type "PYTHONPATH=. .venv/bin/python demo/run_full_ablation.py --mode postcutoff"
Enter
Sleep 5s
