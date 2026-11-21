# Examples

Reference integrations and usage examples for OxDeAI.

Integration levels used below:

- **real framework**: the example imports and runs the framework or SDK named.
- **framework-shaped**: the example builds objects with the framework's tool-call shape and runs no
  framework code.

No example uses a native framework hook or middleware. None is implemented; adapters are called
explicitly from application code.

## Included

- `gpu-guard` - deterministic GPU provisioning guard with audit chain
- `langgraph` - **real framework**: a `@langchain/langgraph` `StateGraph` proposes tool calls; `@oxdeai/langgraph` enforces them in application code after the graph returns (no `ToolNode` or LangGraph hook)
- `openai-tools` - **real SDK** (`demo:openai`, requires `OPENAI_API_KEY`): OpenAI Chat Completions tool calls enforced with `@oxdeai/core` directly (no adapter); the default `start`/`demo` run uses scripted calls
- `crewai` - **framework-shaped** (no CrewAI): `@oxdeai/crewai` on the shared ALLOW/ALLOW/DENY scenario
- `openai-agents-sdk` - **framework-shaped** (no Agents SDK): `@oxdeai/openai-agents` with the shared boundary contract
- `autogen` - **framework-shaped** (no AutoGen): `@oxdeai/autogen` with the shared boundary contract
- `openclaw` - **framework-shaped** (no OpenClaw runtime): `@oxdeai/openclaw` with the canonical authorization boundary flow
- `rust-verifier` - reference-only Rust verifier skeleton (`AuthorizationV1` fail-closed path)
- `settlement-recovery` - 12 synthetic settlement-recovery / replay checks (`pnpm test:settlement-recovery`)
- `agentgram-demo` - deterministic execution boundary for Agentgram actions using the OxDeAI SDK
- `delegation` - `DelegationV1` demo: a parent agent delegates strictly narrowed authority to a child agent
- `execution-boundary-demo` - two-panel UI contrasting an unprotected path against the OxDeAI-guarded path
- `lgf-frappe-pep` - minimal OxDeAI PEP for the LGF-managed Frappe Helpdesk proof of concept
- `non-bypassable-demo` - canonical `Agent -> PEP Gateway -> Protected Upstream` demo: the agent process has no direct call path to the protected upstream
- `sift` - end-to-end demo tracing the integration path from a Sift governance receipt to OxDeAI execution authorization
- `sift-boundary-demo` - terminal demo of Sift-to-OxDeAI execution-boundary enforcement across 4 scenarios
- `reference-sift-oxdeai` - reference implementation of Sift-to-OxDeAI integration with execution-boundary enforcement

## Known-broken at HEAD

The runtime fixes for these are tracked and handled separately from documentation
changes. Do not treat them as verified until fixed.

- `delegation-demo`: `OxDeAIGuard` construction in `src/scenario.ts` omits the
  now-required `trustedKeySets`. Both `pnpm start` and `pnpm terminal` currently
  throw `OxDeAIGuardConfigurationError` on invocation.
- `non-bypassable-openclaw`: `agent.mjs` builds an unsigned, structurally
  incomplete `AuthorizationV1` fixture instead of reusing
  `non-bypassable-demo/auth-fixture.mjs`'s signed fixture. The documented
  ALLOW / DENY_HASH_MISMATCH / REPLAY scenarios do not currently produce the
  documented outcomes.

`non-bypassable-demo` is the canonical, currently-working non-bypassability
example and is unaffected by the above.
