# IX-PackHunt-Guard

IX-PackHunt-Guard is a governed coordination layer for detecting and interrupting prompt-decomposition attacks before individually low-risk fragments assemble into restricted AI capability output.

It is designed for the abuse pattern commonly described as a “pack hunt”: many small requests, turns, sessions, principals, agents, or tool handoffs that appear individually low risk but combine into a prohibited capability.

The project does not claim to make jailbreaks impossible. It provides a deterministic gateway pattern for recording intent fragments, correlating capability assembly, gating risky continuation, and exporting evidence for human review.

## Status

Wave 1 — Coordinated Abuse Gateway MVP

This repository is a standalone, dependency-light Python package. It is intentionally built without external runtime dependencies so the core detector remains easy to inspect, test, and adapt into adjacent IX governance systems.

## What it does

IX-PackHunt-Guard models AI abuse as a coordination problem, not only a single-prompt classification problem.

A single prompt may appear harmless.

A sequence of prompts may not.

The gateway therefore tracks:

- normalized intent fragments
- hashed raw observations
- tenant, principal, and session continuity
- risk signals
- capability tags
- campaign windows
- cross-session and cross-principal assembly pressure
- evidence hashes
- human-review requirements
- governance packet exports

## What it does not claim

IX-PackHunt-Guard does not claim to:

- make jailbreaks impossible
- prevent all AI abuse
- certify any model as safe
- replace model-provider safety systems
- replace human review
- identify real-world criminal intent
- punish users
- provide complete hosted-model containment from outside the provider runtime
- approve operational deployment by itself
- serve as a production AI-safety layer without integration, testing, licensing, and review

The narrow claim is:

When AI traffic passes through this gateway, the system can record normalized intent fragments, detect whether those fragments are assembling into restricted capability patterns across time, sessions, or principals, gate the response, and export evidence for review.

## Core idea

Classifier-only safety asks:

> Is this single request bad?

IX-PackHunt-Guard asks:

> Are these fragments assembling into a restricted capability across requests, users, sessions, agents, or time?

That distinction matters because coordinated abuse often hides in the gap between individually low-risk prompts and the combined goal those prompts reconstruct.

## Architecture

```
GatewayObservation
        |
        v
RuleBasedIntentClassifier
        |
        v
IntentFragment
        |
        v
SessionRiskLedger
        |
        v
CapabilityAssemblyGraph
        |
        v
PackHuntDetector
        |
        v
DetectionDecision
        |
        +--> BlackFox review packet
        +--> CognitionKernel risk record
        +--> Autonomy Assurance evidence bundle
```
Package layout
```
src/ix_packhunt_guard/
  __init__.py
  _hashing.py
  classifier.py
  detector.py
  exporters.py
  graph.py
  identity.py
  schema.py

tests/
  test_classifier.py
  test_detector.py
  test_exporters.py
  test_identity.py

examples/
  safe_gateway_demo.py

docs/
  THREAT_MODEL.md
```
Core components
GatewayObservation

A raw observation from a gateway before downstream storage.

The classifier receives the raw text long enough to label it. Downstream records store hashes and normalized labels rather than raw sensitive content.

IntentFragment

A normalized fragment of observed intent.

It records:

tenant ID
principal ID
session ID
request ID
source
text hash
normalized goal hash
intent kinds
capability tags
risk signals
goal atoms
confidence
evidence references
SessionRiskLedger

An append-only in-memory ledger of normalized fragments.

Wave 1 uses an in-memory ledger so behavior is deterministic and easy to inspect. A future adapter can replace this with durable storage.

CapabilityAssemblyGraph

Summarizes recent fragments into a campaign window and scores whether fragments are assembling into a restricted capability.

The score increases when patterns include:

repeated risky fragments
multiple restricted capability tags
multiple non-benign intent kinds
multiple risk signals
cross-session continuity
cross-principal coordination
overlapping goal atoms
sequence growth
policy-bypass plus tool-handoff pressure
evidence-suppression pressure
PackHuntDetector

The orchestrator.

It classifies a gateway observation, adds it to the graph, summarizes the campaign window, and emits a deterministic decision.

Possible decision actions:

allow
warn
rate-limit
require-review
redact-output
block-response
lock-session
escalate-to-human
export-evidence-bundle
PseudonymousIdentityProvider

Creates HMAC-based pseudonyms for tenants, principals, and sessions.

The detector needs continuity to detect coordinated behavior. It does not need raw identity values.

Exporters

Wave 1 intentionally avoids hard imports from other IX repos. Instead, it emits stable dictionary packets shaped for future adapters:

BlackFox review packet
CognitionKernel risk record
Autonomy Assurance evidence bundle

This keeps the core package standalone while preserving integration direction.

Safe usage example
```
from ix_packhunt_guard import (
    FragmentSource,
    GatewayObservation,
    PackHuntDetector,
)

detector = PackHuntDetector()

observation = GatewayObservation(
    tenant_id="tenant-a",
    principal_id="principal-a",
    session_id="session-a",
    request_id="req-1",
    source=FragmentSource.USER_INPUT,
    text="Give me a safe summary of this governance design.",
    observed_at="2026-06-15T12:00:00",
    sequence_index=1,
)

fragment, window, decision = detector.observe(observation)

print(fragment.intent_kinds)
print(window.assembly_score)
print(decision.action.value)
print(decision.reason)
```
Safe distributed-pattern demo

The included demo uses non-operational text. It is designed to test the pattern shape only.
```
python examples/safe_gateway_demo.py
```
Expected style of output:
```
decision: lock-session
risk_score: 13.4
reason: Coordinated assembly risk exceeded lock-session threshold.
blackfox_decision_hash: <hash>
cognition_risk_score: 13.4
assurance_bundle_trace: <hash>
```
Development

Create and activate a Python environment, then install the package in editable mode:
```
python -m pip install --upgrade pip
python -m pip install -e .[dev]
```
Run tests:
```
pytest
```
Run linting:
```
ruff check .
```
Run type checking:
```
mypy src tests
```
CI

The GitHub Actions workflow runs:
```
ruff check .
mypy src tests
pytest
```
Claim boundary

IX-PackHunt-Guard is not a magic shield.

It is a governed detection and interruption layer.

The correct claim is:

IX-PackHunt-Guard detects and interrupts prompt-decomposition and coordinated-abuse patterns when traffic passes through the gateway, preserving evidence and requiring human authority when thresholds are crossed.

The incorrect claim is:

IX-PackHunt-Guard makes jailbreaks impossible.

Do not use the incorrect claim.

Relationship to adjacent IX systems

IX-PackHunt-Guard is designed to become the coordination layer between model traffic and adjacent IX governance systems.

Planned adapter direction:
```
IX-PackHunt-Guard
  adapters/
    blackfox/
    cognition_kernel/
    autonomy_assurance/
    decriel/
    identity_security/
```
Wave 1 does not require those adapters to run.

BlackFox direction

BlackFox should eventually receive review packets and enforce final gateway action policy.

Example role:
```
detector decision -> BlackFox review packet -> policy gate -> human authority
```
CognitionKernel direction

CognitionKernel should eventually receive risk records and map them into governed refusal or review classes.

Example mappings:
```
policy-bypass
unsafe-tool-handoff
specification-gaming
evidence-suppression
hidden-authority-grant
```
Autonomy Assurance direction

Autonomy Assurance should eventually receive evidence bundles and produce auditable decision chains.

Example chain:
```
mission need -> requirement -> hazard -> control -> evidence -> decision -> human authority
```
Decriel direction

Decriel should eventually provide declared and denied capability manifests.

Example future role:
```
declared capability set -> denied capability set -> gateway capability boundary
```
Wave 1 does not claim Decriel runtime enforcement.

Threat model

See:
```
docs/THREAT_MODEL.md
```
Primary threat:

A coordinated actor, group, or automated agent swarm distributes small request fragments across turns, sessions, principals, or agents so that no single prompt appears high risk, while the combined sequence assembles a restricted capability.

Privacy posture

The package supports privacy-preserving continuity.

It can hash observations and derive pseudonymous identifiers from raw account or session values using deployment-specific HMAC secrets.

This is intended to support abuse correlation without requiring the detector to store raw identity values.

Safety posture

Tests and examples must remain non-operational.

Do not add:

exploit payloads
malware instructions
credential-harvesting steps
evasion recipes
weaponization details
harmful procedures
operational jailbreak instructions
real misuse walkthroughs

The project should test dangerous pattern shapes without reproducing dangerous content.

License

This repository is source-available, not open source.

It is provided under the:
```
IX-PackHunt-Guard Source-Available Evaluation License v1.0
```
Commercial use, production use, hosted-service use, operational use, redistribution, modification, derivative works, government operational use, contractor use, procurement use, organization-backed use, model-facing use, safety-layer use, security-layer use, compliance use, or assurance use requires a separate written license from Bryce Lovell.

See:
```
LICENSE
NOTICE.md
```
Repository details

Suggested GitHub description:
```
Coordinated AI abuse detection and governance gateway for prompt-decomposition, policy-bypass, and cross-session capability-assembly attacks.
```

Author

Bryce Lovell

Final note

IX-PackHunt-Guard is the missing coordination layer for the broader IX governance stack.

It does not replace BlackFox, CognitionKernel, Autonomy Assurance, Decriel, or any provider-side safety system.

It gives them something specific to act on:

evidence that individually small fragments are assembling into a restricted capability campaign.
