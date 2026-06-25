# vhs tape — user-code haystack: the SYSTEM moves the number (0.67 -> 1.00) on the real domain.
# Render:  PATH="$PWD/.tmp/bin:$PATH" vhs demo/recording/usercode_haystack.tape
Output demo/recording/usercode_haystack.gif
Set FontSize 16
Set Width 1340
Set Height 560
Set Theme "Dracula"
Set Padding 16

Type "# User-app code (the product's real domain): does +SAST help the LLM localize?"
Enter
Sleep 700ms
Type "PYTHONPATH=. .venv/bin/python demo/run_haystack_eval.py --mode report --audits usercode32b"
Enter
Sleep 5s
