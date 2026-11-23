# Third-Party Notices & Open-Source Disclosures

**ASTRA (Autonomous Settlement, Tracking & Reconciliation Architecture)**
Copyright (c) 2026 Pinaka AI. Licensed under the [MIT License](./LICENSE).

---

## 1. Scope of Repository License

The MIT License in [`LICENSE`](./LICENSE) applies to all original source code, schemas, synthetic fixtures, UI components, and documentation in this repository authored by Pinaka AI.

- **No Cloud Access or Endorsement:** This repository contains zero credentials, endpoints, or entitlements to Pinaka AI's or any contributor's cloud environments (AWS, GCP, Azure) or proprietary hosted services. Users deploying ASTRA supply their own infrastructure and credentials.
- **No Affiliation:** ASTRA is an independent, clean-room open-source implementation. References to third-party ERP systems (SAP S/4HANA, Oracle Fusion/EBS, Oracle NetSuite, Odoo, Sage Intacct/X3, Microsoft Dynamics) or market categories (including public documentation or patent themes from HighRadius or other vendors) are strictly nominative and for interoperability/benchmarking reference only. No affiliation, endorsement, or proprietary parity is claimed.
- **Not Financial or Audit Advice:** Outputs produced by ASTRA (including match rationales, deduction classifications, forecasts, and audit evidence packages) support internal finance operations and do not constitute formal accounting opinions, SOC attestations, or PCAOB/SOX audit certifications.

---

## 2. Runtime & Development Dependencies

All direct runtime and development dependencies used in `apps/api` and `apps/web` use permissive open-source licenses compatible with MIT distribution:

| Component | Package / Project | License | Usage in ASTRA |
|---|---|---|---|
| Backend API & Worker | `fastapi`, `uvicorn`, `pydantic` | MIT | Domain API, typed contracts, validation |
| Database & Vector Store | `postgresql`, `pgvector`, `psycopg` / `sqlalchemy` | PostgreSQL / MIT | Relational ledger, outbox queue, scoped RAG embeddings |
| Frontend Workbench | `next`, `react`, `react-dom`, `tailwindcss`, `lucide-react` | MIT / ISC | Enterprise Finance Workbench UI |
| Document & XML Parsing | `defusedxml`, `pypdf` / `pdfplumber`, `pillow` | PSF / BSD-3-Clause / HPND | Safe ISO 20022 `camt.053` XML and PDF/image remittance intake |
| Machine Learning Baseline | `scikit-learn`, `numpy`, `scipy` | BSD-3-Clause | Calibrated candidate ranker, subset-sum matcher, evaluation intervals |
| Optional Decision Engine Spike | `laya` (`>=0.5.2`) | Apache-2.0 | Optional feature-flagged `ReasonClassifier` adapter (`ml/laya_adapter.py`); not required to self-host ASTRA |
| Optional High-Volume OCR | `Unlimited-OCR` (Baidu) | Apache-2.0 | Optional multi-page OCR backend (`ml/ocr/`); not bundled or required to self-host ASTRA |

---

## 3. External Connectors, Models, and Provider Terms

- **ERP Connectors (`integrations/erp/`):** Adapter code in this repository is MIT-licensed. Connecting ASTRA to a live SAP, Oracle, NetSuite, Odoo, or Sage instance requires the customer's own valid license and API entitlement with that ERP vendor.
- **Frontier LLM Providers (`integrations/llm/`):** Bring-Your-Own-Key (BYOK) adapters for OpenAI, Anthropic Claude, Google Gemini, Moonshot Kimi, Zhipu GLM, Alibaba Qwen, and self-hosted OpenAI-compatible endpoints are governed by each customer's respective provider agreement.
- **Synthetic Fixtures (`fixtures/synthetic/`):** All bank statements, invoices, remittance PDFs, payer names, tax IDs, and account numbers in this repository are 100% synthetic and generated specifically for automated testing and demonstrations.

---

## 4. Software Bill of Materials (SBOM)

Run `make sbom` (or `python scripts/verify_security.py --generate-sbom`) to generate a machine-readable CycloneDX/SPDX dependency manifest at `docs/security/sbom.json`.
