# tibet-sam

**Sealed Authority Module.**

`tibet-sam` is the bounded-authority primitive in the TIBET four-W
family:

- `tibet-vault` = **WHEN**
- `tibet-keychain` = **WHERE/HOW**
- `tibet-sam` = **WHY**
- `tibet-gateway` = **WHERE-EXEC**

The point of SAM is simple:

- authorize one bounded act
- without releasing the underlying secret to the caller

## Core shape

An agent does not receive a raw API key.

Instead it asks for a sealed authority module that says:

- which intent is allowed
- against which target action
- with which scope constraints
- until when
- under which ephemeral session id

The gateway then:

1. breaks seal inside the boundary
2. validates manifest constraints
3. executes the allowed upstream action
4. destroys the ephemeral session
5. emits a provenance-sealed response

## Sandbox scope

This sketch now emits a real sealed `.tza` capsule, lets a local
gateway runtime read that capsule directly, and emits a sealed gateway
receipt back out.

It provides:

- package shape
- SAM types
- inspect and verify surfaces
- materialization payload shape
- sealed `.tza` materialization
- local gateway runtime for break-seal, validate, execute, destroy
- sealed gateway receipt shape
- human and JSON rendering
- a small CLI to inspect the model

## Commands

```bash
tibet-sam info
tibet-sam types
tibet-sam runtime
tibet-sam inspect /tmp/upload-pypi-v4.sam.tza
tibet-sam verify /tmp/upload-pypi-v4.sam.tza
tibet-sam materialize \
  --intent upload_package \
  --secret-id sec_pypi_001 \
  --target-action /upload/pypi \
  --actor-id jis:humotica:agent.ai \
  --constraint package=tibet-zip \
  --constraint registry=pypi \
  --valid-for-seconds 300 \
  --json

tibet-sam materialize \
  --intent upload_package \
  --secret-id sec_pypi_001 \
  --target-action /upload/pypi \
  --actor-id jis:humotica:agent.ai \
  --constraint package=tibet-zip \
  --constraint registry=pypi \
  --identity-dir /tmp/sam-identity \
  --emit-bundle /tmp/upload-pypi.sam.tza \
  --json

tibet-sam execute \
  --sam-file /tmp/upload-pypi.sam.tza \
  --requested-action /upload/pypi \
  --request-actor jis:humotica:agent.ai \
  --gateway-actor jis:humotica:tibet-gateway \
  --gateway-identity-dir /tmp/gateway-identity \
  --response-bundle /tmp/upload-pypi.sam-receipt.tza \
  --constraint package=tibet-zip \
  --constraint registry=pypi \
  --json
```

Example SAM payload:

- [examples/sam-upload-pypi.json](/srv/jtel-stack/sandbox/ai/codex/tibet-sam-sketch/examples/sam-upload-pypi.json:1)

## Denied Paths

The package should be able to show why a capsule is denied, not only
why a capsule is accepted.

Typical denied cases:

- actor mismatch
- expired SAM
- constraint mismatch

Example:

```bash
tibet-sam execute \
  --sam-file /tmp/upload-pypi-v4.sam.tza \
  --requested-action /upload/pypi \
  --request-actor jis:humotica:wrong.actor \
  --gateway-actor webshop.admin \
  --constraint package=tibet-zip \
  --constraint registry=pypi \
  --json
```

And for a structural check:

```bash
tibet-sam verify /tmp/upload-pypi-v4.sam.tza --json
```

## Current Runtime Boundary

The current sandbox runtime already performs the bounded flow:

1. break seal inside the gateway boundary
2. validate actor, target action, and constraints
3. open an ephemeral gateway session
4. proxy secret use through a local runtime adapter
5. destroy the session
6. emit a sealed receipt

Current local adapters:

- `upload_package` to `/upload/pypi`
- a generic bounded fallback executor for other intents

This is enough to prove the runtime shape end-to-end.
What still remains for production is not the authority flow itself, but
real upstream adapters inside the actual `tibet-gateway` package.

## Release Notes For Package Lift

This sandbox is now mature enough for a lift into `/packages/tibet-sam`
because it already proves:

- sealed authority materialization
- direct `.tza` execution path
- explicit session lifecycle
- sealed receipt emission
- inspect and verify operator surfaces

What is still production-later:

- real upstream adapters inside `tibet-gateway`
- real external secret backends behind `tibet-keychain`
- richer policy lanes and revocation handling

## Intended next steps

- move the sandbox runtime shape into real `tibet-gateway` boundary hooks
- deepen destroy-session semantics around real external adapters
- link to `tibet-keychain` custody records

## Short formulation

SAM authorizes the right to perform one bounded act, without
releasing the underlying secret.
