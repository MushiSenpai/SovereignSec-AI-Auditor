# vhs tape — hard 29-module benchmark, 3 architectures: bare LLM vs one-shot vs agentic.
# Render:  PATH="$PWD/.tmp/bin:$PATH" vhs demo/recording/haystack_v2.tape
Output demo/recording/haystack_v2.gif
Set FontSize 15
Set Width 1360
Set Height 640
Set Theme "Dracula"
Set Padding 16

Type "# Hard benchmark (29 files, 6 CWE classes, decoys): bare LLM vs one-shot vs agentic"
Enter
Sleep 700ms
Type "PYTHONPATH=. .venv/bin/python demo/run_haystack_eval.py --mode report --audits v2"
Enter
Sleep 5s
