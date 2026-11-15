# Media

## Status

Non-normative (developer documentation)






This directory contains short visual demos for repository onboarding.

The demos are lightweight animations of the canonical authorization flow:

- `ALLOW`
- `ALLOW`
- `DENY`
- `verifyEnvelope() => ok`

Diagrams (SVG, hand-written, embedded in the root README):

- [`oxdeai-overview.svg`](./oxdeai-overview.svg): actions crossing the execution boundary (ALLOW, NOT COVERED, REPLAY, DENY)
- [`oxdeai-boundary.svg`](./oxdeai-boundary.svg): PDP, PEP gateway, protected tool and the refused direct call

Edit the SVG source directly; colors follow the logo (`#111111`, `#28C76F`).

Included assets:

- [`oxdeai-demo.tape`](./oxdeai-demo.tape)
- [`oxdeai-demo.gif`](./oxdeai-demo.gif)
- [`oxdeai-demo-openai.gif`](./oxdeai-demo-openai.gif)
- [`oxdeai-demo-langgraph.gif`](./oxdeai-demo-langgraph.gif)
- [`oxdeai-demo-simple-agent.gif`](./oxdeai-demo-simple-agent.gif)

Regeneration:

- canonical source: `vhs docs/media/oxdeai-demo.tape`
- repository fallback: `bash docs/media/render-demo.sh`
