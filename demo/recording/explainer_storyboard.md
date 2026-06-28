# SovereignSec-AI — narrated explainer (storyboard for your portfolio site)

**Render path:** I can't render HeyGen HyperFrames from a CLI agent (the MCP's `compose`/
`render_video` are disabled here — they're for hosted clients). To produce this:
`npx skills add heygen-com/hyperframes` then `/hyperframes` with this storyboard, **or** run it
from a hosted Claude client where the HyperFrames MCP can compose/render. B-roll is ready:
`ablation.gif` and `splitscreen.gif`. Target: 60–75s, 1920×1080.

| # | Duration | On-screen | Narration |
|---|---|---|---|
| 1 | 0–8s | Dark. A code file slides toward a "ChatGPT" cloud and hits a red ⛔. Text: *"Your code can't leave the building."* | "Banks, defense, healthcare — they legally can't paste proprietary code into a hosted AI. So they don't get AI code security at all." |
| 2 | 8–16s | Logo: **SovereignSec-AI**. A single workstation (RTX 5090) glows; a padlock; "zero egress". | "SovereignSec-AI is a fully local, agentic security auditor. It reviews an entire repo and never sends a byte off the machine." |
| 3 | 16–32s | Animated 5-layer stack: graph+taint → SAST → agent → validation. Arrows light up in sequence. | "It builds a cross-file taint graph, runs deterministic scanners, and an agent orchestrates them — forming a hypothesis, tracing it across files, and proving it." |
| 4 | 32–46s | Play `ablation.gif`. Highlight: **Semgrep alone R=0.5 (misses the cross-file trail) → full system P=R=1.0**. | "Single-file scanners can't follow a bug across files — here a SQL injection flowing through three files. The taint engine traces the full source→sink path and proves it, with no false positives on the safe lookalike." |
| 5 | 46–58s | Play `splitscreen.gif`: scan + GPU + the egress monitor flat at **0 B/s**. | "Watch the network: zero egress while it audits. The code, and the AI, stay on your hardware." |
| 6 | 58–68s | Stat cards: *"879 real CVE pairs mined · 4-bit QLoRA on Blackwell · fully air-gapped"*. | "Trained on real vulnerability data, fine-tuned locally on a single GPU, and measured honestly — every number reproducible." |
| 7 | 68–75s | **your portfolio site** · "Sovereign AI Deployment". | "Sovereign AI deployment, for teams whose code can't leave. your portfolio site." |

**Tone:** confident, technical, understated (the buyer is a security/eng lead, not a consumer).
**Honesty note:** keep claims to what's measured (the ablation, the egress shot, the mined-data
count) — no "finds any vuln" overreach. The credibility *is* the pitch.
