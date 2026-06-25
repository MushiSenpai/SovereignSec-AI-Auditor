# vhs tape — after the coverage push (SSRF/path/deser rules): agentic 0.41->0.69, hybrid 0.97.
# Render:  PATH="$PWD/.tmp/bin:$PATH" vhs demo/recording/haystack_v2cov.tape
Output demo/recording/haystack_v2cov.gif
Set FontSize 15
Set Width 1360
Set Height 660
Set Theme "Dracula"
Set Padding 16

Type "# After the coverage push (SSRF/path/deser rules + get_json source): 4 architectures"
Enter
Sleep 700ms
Type "PYTHONPATH=. .venv/bin/python demo/run_haystack_eval.py --mode report --audits v2cov"
Enter
Sleep 5s
