# PSN Core Definition

## Immutable Core of Personal Secure Node (PSN)

**Status:** Core Specification (Non-Extensible)

This document defines the immutable core properties of the Personal Secure Node (PSN).

Any system that does not satisfy **all** properties defined here **MUST NOT** be referred to as a PSN.

This file exists to prevent conceptual drift, feature inflation, and re-centralization during future development.

---

## Core Principle 1: Individual-Controlled Identity

* A PSN identity **must be controlled by the individual user**, not by any platform, organization, or service provider.
* Identity issuance, rotation, and revocation **must not require approval** from a third party.
* The canonical identifier **must be resolvable via an open, global naming system** (e.g., domain name system or equivalent).

If an identity can be suspended, deleted, or reassigned by an external authority, it violates the PSN definition.

---

## Core Principle 2: Verifiable, End-to-End Communication

* All communications between PSN nodes **must be cryptographically verifiable end-to-end**.
* Intermediary servers or relays **must not have access to plaintext content**.
* Identity verification **must be technically provable**, not reputation- or promise-based.

If communication security relies on trusting an operator or service provider, it is not PSN-compliant.

---

## Core Principle 3: Explicit Responsibility Binding

* Every PSN instance **binds digital actions to a specific human operator or accountable entity**.
* PSN explicitly rejects anonymous-by-default operation.
* Responsibility for data, identity usage, and communication **cannot be delegated to the software author or protocol designer**.

If responsibility is ambiguous or structurally deflected, the system is not a PSN.

---

## Core Principle 4: Local Authority Over Data and Behavior

* A PSN **must operate as a clear digital boundary** under the user's authority.
* Data storage, access permissions, and network behavior **must be inspectable and controllable by the user**.
* Default behavior must favor minimal access and explicit authorization.

If the system performs significant actions without the user's awareness or control, it violates PSN principles.

---

## Core Principle 5: Protocol Over Platform

* PSN is defined as an **open protocol and reference architecture**, not as a centralized service.
* No single organization may be required for the protocol's continued existence.
* Multiple independent implementations **must be possible** without coordination or permission.

If the system ceases to function when a specific platform disappears, it is not PSN.

---

## Explicit Non-Goals

The following are **intentionally excluded** from the PSN core:

* Content moderation or distribution
* Social networking features
* Economic incentive systems or tokens
* Anonymity or identity obfuscation mechanisms
* User behavior scoring or ranking

These features may exist in adjacent systems but are not part of PSN.

---

## Minimal Compliance Test (Conceptual)

A system may be considered PSN-compliant **only if**:

1. Two individuals, each controlling their own PSN instance
2. Using independently obtained identifiers
3. Can establish a verifiable, encrypted communication channel
4. Without relying on a shared platform operator
5. While retaining clear responsibility for their actions

Failure at any point invalidates PSN compliance.

---

## Closing Statement

The PSN core is intentionally small.

Its purpose is not to solve every problem, but to define a **non-negotiable foundation** upon which systems may be built without violating human digital sovereignty.

Any extension that weakens these principles should be considered a separate system, not an evolution of PSN.
