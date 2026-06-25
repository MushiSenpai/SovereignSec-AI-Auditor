# vhs tape — haystack localization (toy 1.0 vs real-file 0.07): the reality check.
# Render:  PATH="$PWD/.tmp/bin:$PATH" vhs demo/recording/haystack.tape
Output demo/recording/haystack.gif
Set FontSize 15
Set Width 1340
Set Height 600
Set Theme "Dracula"
Set Padding 16

Type "# Localize the vuln among ~14 functions in real CVE files — bare LLM vs +SAST system"
Enter
Sleep 700ms
Type "PYTHONPATH=. .venv/bin/python demo/run_haystack_eval.py --mode report --audits base32b"
Enter
Sleep 5s
