# Threat Model

## Protected asset

The protected asset is the boundary between high-capability model reasoning and
unrestricted output or tool execution.

## Primary threat

A coordinated actor, group, or automated agent swarm distributes small request
fragments across turns, sessions, principals, or agents so that no single prompt
appears high risk, while the combined sequence assembles a restricted
capability.

## Security objective

Detect and interrupt capability assembly before unrestricted output or tool
execution occurs.

## Trust boundary

The model is not trusted to approve its own output.

Classifier labels are not trusted as final truth.

The detector emits evidence-bound decisions that can require human review before
continuation.

## In-scope attack patterns

- prompt decomposition
- low-and-slow probing
- cross-session continuation
- cross-principal coordination
- policy-bypass pressure
- context laundering
- tool-handoff pressure
- authority escalation attempts
- evidence suppression pressure
- capability assembly across time

## Out-of-scope claims

IX-PackHunt-Guard does not claim:

- perfect jailbreak prevention
- criminal attribution
- universal hosted-model containment
- replacement of provider-side safety systems
- autonomous punishment
- account enforcement without operator policy
- certification that a model is safe
- certification that a model is impossible to abuse

## Fail-closed conditions

A gateway should fail closed when:

- restricted capability labels combine with policy-bypass pressure
- evidence-suppression pressure is observed in a restricted context
- a campaign score crosses the block threshold
- a campaign score crosses the lock-session threshold
- human review is required but unavailable
- evidence needed for review cannot be preserved

## Evidence requirements

Every reviewable decision should preserve:

- latest fragment hash
- campaign window hash
- decision hash
- timestamp
- tenant pseudonym
- principal/session pseudonyms
- trigger signals
- reason string
- claim boundary
- human authority requirement

## Safe simulation rule

Tests, examples, and fixtures must use non-operational patterns only.

Do not add exploit payloads, credential-harvesting steps, malware instructions,
evasion recipes, weaponization steps, or other operational misuse content.
