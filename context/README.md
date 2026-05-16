# Context

This folder contains public design context for the project: a prototype for **verifiable chain of custody for encrypted mobile evidence**.

The folder is safe for publication only if it remains limited to public architecture, protocol concepts, threat modeling, privacy constraints, MVP scope, roadmap, and synthetic examples.

## What this folder includes

- Project summary
- Problem statement
- Product principles
- System architecture
- Protocol overview (event types, payloads, report/freeze, timestamp semantics)
- Public data model (snapshots, attestations, ledger, key grants, reports, freezes)
- Threat model
- Privacy and abuse constraints
- Security assumptions (including identity lifecycle and timestamp handling)
- MVP scope
- Roadmap
- Demo scenarios
- Glossary
- Publication checklist
- Security reporting guidance
- Public implementation notes (cryptographic specifics, identity lifecycle, timestamps)
- Canonical encoding spec (canonical JSON, signed-body, base64url, ECDSA, AES-GCM, HKDF, hash chain)
- Synthetic JSON payload examples (`examples/`)
- Mermaid architecture diagrams (`assets/`)

## File index

| File | Purpose |
|------|---------|
| `00_project_summary.md` | One-page project summary and core claim |
| `01_problem_statement.md` | Problem domain and design challenge |
| `02_product_principles.md` | 12 product principles |
| `03_system_architecture.md` | iOS app modules, backend modules, data flow |
| `04_protocol_overview.md` | Protocol payloads, event types, report/freeze, timestamp semantics, replay protection |
| `05_data_model_public.md` | Public-safe data models for all entities |
| `06_threat_model.md` | Assets, trust boundaries, threat actors, attack classes |
| `07_privacy_and_abuse.md` | Privacy model, E2EE tradeoffs, acceptable-use boundaries |
| `08_security_assumptions.md` | Device, crypto, backend, witness, identity lifecycle, time, network assumptions |
| `09_mvp_scope.md` | Must-implement features and success criteria |
| `10_roadmap.md` | Near/medium/long-term future work |
| `11_demo_scenarios.md` | 5 fictional end-to-end demo scenarios |
| `12_glossary.md` | Key terms and preferred language |
| `13_publication_checklist.md` | Review checklist before publishing |
| `14_security_reporting.md` | Security and abuse reporting procedures |
| `15_implementation_notes_public.md` | Cryptographic specifics, identity lifecycle, timestamp handling, repo hygiene |
| `16_canonical_encoding.md` | Canonical encoding (v0.1): canonical JSON, signed-body, base64url, ECDSA, AES-GCM, HKDF, hash chain |

## What this folder must not include

Do not commit:

- real photos, audio, video, or evidence samples
- real names, emails, phone numbers, addresses, or personal identifiers
- exact GPS coordinates or sensitive location traces
- faces, license plates, or identifying screenshots
- private keys, seed phrases, certificates, provisioning profiles, or signing material
- API keys, database credentials, JWTs, access tokens, `.env` files, or secrets
- Apple Team IDs, production bundle identifiers, or sensitive deployment identifiers
- real device identifiers, serial numbers, IP addresses, or production logs
- internal exploit notes or step-by-step abuse instructions

## Publication principle

The `/context` folder should be transparent enough to build trust and support collaboration, but abstract enough to avoid exposing private data, sensitive operational details, or abuse-enabling information.
