# PSN Protocol Specification

## Personal Secure Node Protocol (PSNP)

**Version:** v0.1
**Status:** Draft – Minimal, Non-Extensible

This document defines the minimal wire-level and logical protocol required
for two Personal Secure Nodes (PSN) to establish a verifiable, end-to-end
encrypted communication channel.

This protocol is intentionally minimal. Any feature not explicitly defined
here is considered out of scope for PSN v0.1.

---

## 1. Protocol Goals

PSNP v0.1 is designed to achieve exactly one goal:

> Enable two independently operated PSN instances to authenticate each other
> and exchange encrypted messages without relying on a shared platform or
> trusted intermediary.

Non-goals include scalability, anonymity, group communication, and user
experience optimization.

---

## 2. Terminology

* **Node**: A running instance of a Personal Secure Node.
* **Operator**: The human or accountable entity controlling a Node.
* **Identifier (ID)**: A globally resolvable identifier bound to a Node.
* **Peer**: A remote Node participating in communication.

---

## 3. Identifier and Key Binding

### 3.1 Identifier Format

* Each Node MUST have exactly one canonical identifier.
* The identifier MUST be globally resolvable and human-readable.
* v0.1 RECOMMENDS Fully Qualified Domain Names (FQDN).

Example:

```
alice.example
```

---

### 3.2 Public Key Publication

* Each Node MUST publish a public identity key.
* The public key MUST be retrievable via a globally accessible resolution
  mechanism.
* v0.1 RECOMMENDS publishing the key fingerprint via DNS TXT records.

Example DNS TXT record:

```
psn-key=SHA256:BASE64ENCODEDKEY
```

DNSSEC SHOULD be enabled where possible.

---

## 4. Cryptographic Primitives (Recommended)

To reduce ambiguity, PSNP v0.1 recommends the following primitives:

* Key Exchange: X25519
* Identity Signatures: Ed25519
* Symmetric Encryption: AES-256-GCM or ChaCha20-Poly1305
* Hash Function: SHA-256

Alternative primitives MAY be used only if they provide equivalent security
properties.

---

## 5. Connection Establishment Flow

### 5.1 Overview

The connection establishment consists of four phases:

1. Identifier Resolution
2. Identity Verification
3. Session Key Agreement
4. Secure Channel Confirmation

---

### 5.2 Step-by-Step Handshake

#### Step 1: Resolve Peer Identifier

* Operator provides peer identifier (e.g., `bob.example`).
* Node resolves identifier to obtain peer public identity key.

If resolution fails, the connection MUST abort.

---

#### Step 2: Verify Peer Identity

* Node verifies:

  * Key format validity
  * Optional DNSSEC chain

If verification fails, the connection MUST abort.

---

#### Step 3: Ephemeral Key Exchange

* Each Node generates an ephemeral key pair.
* Nodes exchange ephemeral public keys.
* Shared session secret is derived using X25519.

Ephemeral keys MUST NOT be reused.

---

#### Step 4: Identity Binding

* Each Node signs the session parameters using its long-term identity key.
* Signed parameters include:

  * Both identifiers
  * Both ephemeral public keys
  * Timestamp (optional)

Failure to validate signatures MUST abort the connection.

---

#### Step 5: Secure Channel Confirmation

* Nodes derive symmetric session keys.
* A test encrypted message MAY be exchanged to confirm channel integrity.

At this point, the secure channel is established.

---

## 6. Message Format (v0.1)

### 6.1 Encrypted Payload Structure

Each message MUST include:

```
{
  header: {
    protocol_version,
    sender_id,
    receiver_id,
    message_type,
    sequence_number
  },
  ciphertext,
  authentication_tag
}
```

The header MAY be authenticated but MUST NOT reveal message content.

---

### 6.2 Message Types

v0.1 defines only the following message types:

* HANDSHAKE
* HANDSHAKE_ACK
* DATA
* TERMINATE

Any undefined message type MUST be rejected.

---

## 7. Audit and Logging Requirements

Each Node MUST locally record:

* Peer identifier
* Connection timestamp
* Session identifier
* Termination reason

Logs MUST NOT contain plaintext message content.

---

## 8. Failure Handling

* Any protocol violation MUST result in immediate termination.
* Nodes MUST NOT attempt automatic retries that bypass verification steps.

Explicit failure is preferred over silent recovery.

---

## 9. Security Considerations

### 9.1 Threats Addressed

* Man-in-the-middle attacks
* Replay attacks (with sequence numbers)
* Impersonation

### 9.2 Threats Not Addressed (v0.1)

* Traffic analysis
* Denial-of-service attacks
* Compromised endpoints

---

## 10. Versioning and Compatibility

* Protocol versions MUST be explicitly declared.
* Backward compatibility is NOT required in v0.x.

Breaking changes are acceptable until v1.0.

---

## 11. Closing Statement

PSNP v0.1 intentionally limits itself to the smallest verifiable unit of
secure, accountable communication.

Any extension beyond this specification MUST be treated as a separate
protocol layer, not a modification of the PSN core.
