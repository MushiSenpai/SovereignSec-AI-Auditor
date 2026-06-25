# vhs tape — cross-file precision: system 1.0/1.0 vs per-file LLM 0.60/0.25.
# Render:  PATH="$PWD/.tmp/bin:$PATH" vhs demo/recording/crossfile_precision.tape
Output demo/recording/crossfile_precision.gif
Set FontSize 15
Set Width 1360
Set Height 560
Set Theme "Dracula"
Set Padding 16

Type "# Cross-file precision: per-file LLM vs the system (taint follows user input across files)"
Enter
Sleep 700ms
Type "PYTHONPATH=. .venv/bin/python demo/run_crossfile_precision.py --mode report"
Enter
Sleep 5s
