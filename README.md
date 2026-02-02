# Personal Secure Node (PSN)
A Human-Centric Internet Primitive
Author: Fangfang Ye  
First Public Release: 2026-02-02  

This repository contains the original technical whitepaper and origin
statement of the Personal Secure Node (PSN) concept.

PSN is an open, non-anonymous, human-centric internet primitive designed
to restore individual sovereignty over digital identity and communication.

This repository serves as a public, timestamped record of origin.

Version: v0.1 (Origin Draft)
Author: Fang Ye
Date: 2026-02-02

Abstract

The Personal Secure Node (PSN) is a human-centric internet primitive designed to restore individual sovereignty over digital identity, communication, and data. By combining self-hosted identity, verifiable cryptographic communication, and explicit responsibility boundaries, PSN enables individuals to regain final control over their digital behavior without relying on opaque platforms or unverifiable trust assumptions.

PSN is not an anonymous network, not a dark web system, and not a content platform. Its sole objective is to allow individuals to clearly understand and decide:

Who is my device working for, and is it acting according to my will?

1. Motivation
1.1 Structural Problems of the Current Internet

Modern internet infrastructure exhibits several systemic flaws:

Identity Centralization – Digital identities are issued, controlled, and revoked by platforms.

Responsibility Inversion – Platforms control data while individuals bear legal and security risks.

Opaque Device Behavior – Network activity and permission usage are not interpretable by ordinary users.

Trust by Promise – Security relies on institutional assurances rather than verifiable mechanisms.

1.2 Core Assertion

If individuals cannot assume responsibility for their own digital boundaries, concepts such as security, freedom, and governance remain symbolic rather than real.

2. Design Principles
P1. Self-Hosted Identity (Non-Anonymous)

Identities must be verifiable, portable, and inheritable without dependence on centralized issuers.

P2. Zero Trust by Default

No network, application, or device is trusted implicitly. All access requires explicit authorization.

P3. Explainable Behavior

All critical system actions must be observable, auditable, and comprehensible to humans.

P4. Protocol over Platform

PSN is defined as an open protocol with reference implementations, independent of any operator.

3. System Definition
3.1 What is PSN

A Personal Secure Node is a user-controlled server that:

Anchors personal digital identity

Serves as a cryptographic trust root for communication

Defines a secure boundary for data and permissions

3.2 What PSN Is Not

A social network

A content distribution platform

An anonymity system

A cryptocurrency network

4. High-Level Architecture

A PSN operates as an intermediary between user devices and external nodes, enforcing cryptographic verification and access control while remaining data-neutral.

5. Identity System
5.1 Identifier Scheme

User ID: Fully Qualified Domain Name (FQDN)

Key Publication: DNS TXT records

Integrity Protection: DNSSEC recommended

5.2 Key Management

Each PSN maintains:

A long-term master identity key

Rotatable communication sub-keys

Optional multi-device authorization keys

5.3 Authentication Flow

Resolve peer domain

Retrieve public key via DNS

Verify cryptographic signature

Establish encrypted channel

6. Communication Model
6.1 Principles

End-to-end encryption

No server-side plaintext storage

PSN acts solely as relay and policy enforcement point

6.2 Minimal Capabilities (v0.1)

Peer-to-peer messaging

Peer-to-peer file transfer

No group communication

7. Audit and Transparency
7.1 Logged Events

Network access attempts

Identity requests

Permission changes

Device pairing actions

7.2 Properties

Local-only storage

Hash-chain integrity

User-accessible review

8. Responsibility and Legal Boundaries
8.1 PSN Software Provider

Publishes open-source code

Provides documentation and security updates

Does not operate or access user data

8.2 PSN User

Users assume full responsibility for identities, data, and actions performed through their node.

8.3 Legal Positioning

PSN functions as a private server and cryptographic tool, not a public communications platform.

9. Threat Model
9.1 Considered Threats

Man-in-the-middle attacks

DNS poisoning

Malicious clients

Private key compromise

9.2 Out-of-Scope (v0.1)

User-intentional illegal activity

Social engineering attacks

Fully compromised endpoints

10. Roadmap
v0.1

Single-node deployment

Single-user identity

Command-line interface

v0.2

Multi-device support

Basic UI

Automated key rotation

v1.0

Developer APIs

Plugin architecture

Independent security audits

11. Conclusion

PSN does not promise utopia. It offers a minimal, verifiable foundation that returns the authority to determine digital control back to the individual.

Origin Statement

This document records the original conception of the Personal Secure Node (PSN) by Fang Ye, based on lived experience as an overseas IT worker confronting constrained communication environments and opaque digital control systems. This whitepaper establishes a timestamped, public technical origin for the PSN concept.

The immutable core principles of PSN are defined in [psn-core.md](./psn-core.md).
Any system not satisfying these principles MUST NOT be referred to as PSN.

- [PSN Core Definition](./psn-core.md)
- [PSN Protocol Specification v0.1](./psn-protocol.md)
