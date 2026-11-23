# ASTRA Engineering Specification & Requirement Crosswalk (`docs/BUILD_SPEC.md`)

Copyright (c) 2026 Pinaka AI. Licensed under the MIT License.

---

## Section 0: Open ERP Mandate & Zero-Leak AWS Isolation Boundary

1. **Open ERP Integration Mandate**: ASTRA provides an open, vendor-neutral `ARLedger` / `ERPConnector` SPI (`integrations/erp/`) with first-class adapters for **SAP S/4HANA**, **Oracle Fusion / EBS**, **Oracle NetSuite**, **Odoo**, **Sage (Intacct / X3)**, and a **Universal REST / CSV-SFTP / Scoped MCP Adapter**, paired with a No-Code ERP Mapping & Dry-Run Wizard and an offline Multi-ERP Mock Server.
2. **Zero-Leak AWS Sandbox Boundary**: The public repository (`pinaka-cash-apps`) must never contain or access the developer's personal AWS resources. All personal AWS state, `.tfvars`, account IDs, ARNs, and endpoints remain outside the repository (`../.astra-aws-sandbox/`). Six zero-trust layers enforce this:
   - No static AWS keys accepted in app configuration;
   - Private SSM Session Manager port-forwarding (zero `0.0.0.0/0` public ingress on sandbox resources);
   - Default `ASTRA_EXECUTION_POLICY=local-no-egress` blocking IMDS (`169.254.169.254`) and `*.amazonaws.com` in OSS builds;
   - Automated `.git/hooks/pre-commit` and `.git/hooks/pre-push` scanners (`scripts/verify_security.py`);
   - Ephemeral TTL tags + AWS Budget alarms;
   - UI `ASTRA_DEMO_CAPTURE_MODE=true` hostname/identifier sanitizer for demo video recording.

---

## Part 1: ASTRA | AntiGravity Engineering Brief

You are the lead engineering team for ASTRA, Autonomous Settlement, Tracking & Reconciliation Architecture. Implement an original, self-hosted, MIT-licensed enterprise cash-application product. Build it for AR analysts, controllers, Treasury, FP&A, IT administrators and internal and external auditors. The differentiator is not a chatbot: it is cash application whose decisions can be traced to evidence, whose integrations are configurable by customer IT, and whose short-pay work is informed by Pinaka AI without outsourcing accounting judgment to a model.

### 1.1 Start Here
1. Enumerate local inputs in `docs/input-register.md` with owner, permission, revision, availability, summary and implementation impact. Private inputs, operational traces, URLs with embedded tokens and real data stay outside public Git.
2. Reconcile the ASTRA brief with the earlier Agentic Cash Application prompt via the crosswalk in Part 3 below; never override financial or security controls.
3. Keep `AGENTS.md` concise at the root pointing to `docs/BUILD_SPEC.md`.
4. Map every requirement in `docs/requirements-traceability.md` to owner, implementation path, acceptance test, evidence, release status and external dependencies. Default unavailable external services to explicitly labeled mocks (`automated fixture passed`).
5. Keep the repo local until release review; do not incur AWS charges or enable live posting without specific approval.

### 1.2 Clean-Room, Patent Themes & Licensing Boundaries
- **Clean-room benchmark (`documentation-based`)**: Public descriptions define inputs, outcomes, and edge cases; all algorithms, schemas, and UI are independently implemented.
- **Public patent themes noted for FTO awareness**: Image quality (`US11758071B1`, `US12154357B2`), document extraction (`US12254711B2`, `US20260099505A1`), remittance mapping (`EP4579565A1`).
- **Licensing**: Unmodified SPDX MIT License (`Copyright (c) 2026 Pinaka AI`), `THIRD_PARTY_NOTICES.md`, SBOM (`docs/security/sbom.json`), and 100% synthetic fixtures.

### 1.3 Architecture, Data Model & State Machine
- **Monorepo Layout**: `apps/web` (Next.js TypeScript), `apps/api` (Python FastAPI + durable worker), `packages/contracts`, `integrations`, `ml`, `infra`, `docs`, `fixtures/synthetic`, `tests`, `.github/workflows`.
- **Exact Money Math**: Integer minor units (`amount_minor`) + ISO 4217 currency code + explicit currency exponent (`2` for USD/EUR, `0` for JPY, `3` for KWD).
- **Receipt Lifecycle State Machine**:
  `received -> normalized -> matched | needs_review | unapplied | quarantined -> approved_as_required -> posting_pending -> posted | posting_failed -> reconciled` (with `reversed` modeled as an immutable linked event).
- **Accounting Identity**:
  $$\text{Receipt Total} = \text{Applied Cash Allocations} + \text{Unapplied Cash}$$
  Processor fees are modeled explicitly in the gross-to-net bridge; deductions remain open AR residuals (`DeductionCaseV1`).

### 1.4 Release Measurement & Hard Gates
- **Primary Metric (Correct Auto-Match Rate)**: $\text{Correctly & Fully Auto-Allocated Incoming Receipts} \div \text{Eligible Incoming Receipts}$ (production promotion bar: $\ge 96\%$, precision $\ge 99.5\%$, 47/47 `SEC-xx` checks evidenced, $\ge 100$ simultaneous users verified).
- **Experimental Cohorts**: Compare same-cohort `rules_only`, `rules_plus_ml`, and `rules_plus_ml_plus_context` on $\ge 2,000$ synthetic adjudicated receipts with 95% Wilson/bootstrap confidence intervals.

---

## Part 2: Experimental Agentic Cash Application System Prompt (Harmonized)

### 2.1 Hypotheses Under Test (`H1`–`H4`)
- **H1**: Agents reasoning over context (history, emails, contracts, disputes) resolve more exceptions than static rules.
- **H2**: Human-readable rationales with exact evidence pointers (`doc:page:bbox`) raise controller and auditor trust.
- **H3**: Closed learning loop ($N=3$ confirmed reviewer corrections + regression check) lifts auto-match rate safely.
- **H4**: Unified handling of short-pays, deductions (`DeductionCaseV1`), and unapplied cash reduces downstream rework.

### 2.2 Ten Coordinated Agent Roles (`ml/agents/`)
1. **Intake Agent**: Multi-channel ingestion (`camt.053`, CSV, BAI2/MT940/EDI 820 profiles, Stripe test settlement, email/PDF, virtual-card processor token verification inside PCI-safe boundary).
2. **Document Quality Agent**: Scores resolution (DPI), skew, and noise; applies deterministic deskew, contrast normalization, and stamp/noise cleanup below 300 DPI.
3. **Extraction Agent**: Extracts payer, amount, currency, date, invoice/credit memo refs, discounts, deductions, and reason spans with bounding-box locators (`doc_id:page:bbox`).
4. **Correction Agent**: Detects OCR confusables (`0/O`, `1/I/l`, `5/S`, `8/B`) using per-payer invoice format regexes and validates candidates against open AR balances.
5. **Pattern Agent**: Maintains per-payer profile (reference field habit, typical payment delay, bundling, discount habit).
6. **Matching Agent**: 4-tier matching (1: Exact reference + amount; 2: Reference + explainable variance; 3: Bounded subset-sum over open AR; 4: Calibrated ML ranker with margin gate).
7. **Exception Agent**: Routes and investigates short-pays, overpayments, unidentified payers, duplicates, wrong-entity receipts, and stale snapshots.
8. **Deduction Agent**: Builds `DeductionCaseV1`, classifies reason codes (baseline + optional feature-flagged `LayaReasonClassifier`), correlates `RiskSnapshotV1` from Pinaka AI.
9. **Communication Agent**: Drafts missing-remittance or short-pay clarification messages via Gmail/Microsoft Graph preview + approval-gated local mail sink.
10. **Audit Agent**: Emits hash-chained append-only audit logs and plain-language 20-second controller rationales.

---

## Part 3: Requirement-to-Test Reconciliation Crosswalk

| Theme | ASTRA Brief Requirement | Agentic Prompt Requirement | Harmonized Implementation & Stricter Control Rule | Acceptance Test |
|---|---|---|---|---|
| **Auto-Post Policy** | Precision $\ge 99.5\%$; deterministic policy decides eligibility; no inferred auto-post without independent signals & margin. | Confidence $\ge 0.95$, amount $\le$ limit, exact or explainable match -> Auto-post; inferred match never auto-posts above risk limit. | Both rules enforced: Auto-post requires `confidence >= 0.95`, `margin >= 0.15`, `tier in (1, 2)`, `amount_minor <= policy.auto_post_limit_minor`, valid open period, and fresh AR snapshot. | `tests/test_matching_policy.py::test_auto_post_gates` |
| **Virtual Cards (VCC)** | Virtual-card payments are settlement evidence via processor token/reference only; never store card credentials. | Verify sender (SPF/DKIM/allowlist), match expected payer/amount, process only inside PCI-safe boundary; mask PANs. | Reject raw PANs at ingress (`SEC-19`/`SEC-26`); accept only tokenized processor references (`vcc_token_ref`) with sender domain & SPF/DKIM verification flag. | `tests/test_intake_security.py::test_vcc_token_boundary` |
| **Learning Loop** | Never train from raw model feedback or auto-promote live; require approval and rollback (`SEC-45`). | Promote per-payer rule candidate only after $N=3$ consistent confirmations and passing historical regression test. | $N=3$ consistent analyst confirmations generate a `RuleCandidate` that runs automated historical regression and requires Controller approval (`SEC-09`) before activation. | `tests/test_learning_loop.py::test_n3_rule_promotion_and_sod` |
| **Short-Pay & Pinaka / Laya** | Deductions are AR residuals (`DeductionCaseV1`); Pinaka (`RiskSnapshotV1`) informs priority only; Laya (`0.5.2`) evaluated behind feature flag. | Deduction Agent classifies reason, links claims, proposes coding; never writes off without approval. | Cash allocation posts only received cash; residual opens `DeductionCaseV1`; observed reason vs. predicted reason vs. Pinaka delay horizon remain separate columns; write-offs require Controller maker-checker sign-off. | `tests/test_deductions_pinaka_laya.py` |
| **LLM & Tool Boundary** | Chat returns `AnswerV1`; Reports use declarative `ReportSpecV1`; no direct write tools in chat (`SEC-43`, `SEC-44`). | Section 7 defines function tools (`post_cash`, `send_message`, etc.) gated by policy. | Structured pipeline tools in `ml/agents/` are invoked by deterministic backend workflow code, never exposed to free-form chat prompts. Chat is strictly read-only + proposal draft. | `tests/test_chat_grounding_and_sec44.py` |
