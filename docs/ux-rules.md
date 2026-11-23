# ASTRA Enterprise UX & Accessibility Rules (`docs/ux-rules.md`)

This document codifies the mandatory UI, interaction, visual identity, and accessibility rules for ASTRA (`apps/web`), synthesizing the ASTRA Engineering Brief (`docs/BUILD_SPEC.md`), the Enterprise UX System patterns, Apple HIG clarity principles, and Anti-Slop quality filters.

---

## 1. Core Design Philosophy

1. **Dense, Calm Finance Operations Workbench — Not a Marketing Landing Page**
   - Boot directly into the operational workspace (`Workbench`, `Match Queue`, `Split-View Match Review`, `Short-Pay & Pinaka`, `ERP Integrations`, `Chat & Reports`, `Audit Evidence`, `Administration`).
   - Never render fake AI hype banners ("NEXT-GEN AI 2.0", sparkle emojis, fabricated latency ticker, or decorative gradients).
   - Keep financial evidence, policy status, and control totals directly beside action buttons—never buried inside a chat drawer.

2. **Persistent Context & Operational Mode Banner**
   - Top shell bar always displays and controls:
     - **Legal Entity Switcher** (e.g., `US-CORP-01`, `EU-GMBH-02`, `IN-PVT-03`) — strictly scopes all queries and exports (`SEC-07`).
     - **Accounting Period / Date Window** (with open/closed period indicator and UTC / company timezone toggle).
     - **Display / Functional Currency Filter** (showing exact minor-unit precision per ISO 4217 exponent).
     - **Active Role Persona & SoD Badge** (showing allowed vs. maker-checker-restricted actions).
   - **Explicit Mode Banner (Non-Color-Sole Cue):**
     - `DEMO MODE — Synthetic Data Only | No External Egress or Live ERP Posting`
     - `SHADOW / UAT MODE — Read-Only Ingestion | ERP Posting Switch Locked OFF`
     - `LIVE PRODUCTION MODE — Authorized OIDC Session | Maker-Checker Posting Active`
     - When `ASTRA_DEMO_CAPTURE_MODE=true` is enabled for video recording, all environment URLs and infrastructure identifiers are automatically masked to `astra.pinaka.local`.

---

## 2. Brand Identity & Color Tokens

- **Brand Mark (`ASTRA-Logo.svg`)**: Clean typographic monogram featuring a bold **Bebas Neue `'A'` inside a Circle** paired with the `ASTRA` wordmark (no decorative graphic logo). Shipped in 4 variants under `apps/web/public/brand/`:
  - `ASTRA-Logo.svg` (full dark-shell lockup)
  - `ASTRA-Logo-Light.svg` (light-background lockup)
  - `ASTRA-Mark.svg` (monogram/icon mark)
  - `favicon.svg` (high-contrast small icon)
- **Color Palette & WCAG 2.2 AA Contrast Rules**:
  - `--astra-navy`: `#111D32` (Navigation shell & header background; paired with `#F6F8FB` text -> 14.8:1 contrast ratio, passes AAA)
  - `--astra-surface`: `#F6F8FB` (Primary light workbench background)
  - `--astra-card`: `#FFFFFF` (Elevated table/card surface with `1px solid #D8E0EC` border)
  - `--astra-jade`: `#40AFA7` (Brand accent; for text/badges on light backgrounds use darkened semantic token `#136F68` with `#E6F6F4` fill -> 5.9:1 contrast ratio, passes AA)
  - `--astra-gold`: `#DEC189` (Ring/highlight accent on dark `#111D32` shell -> 8.1:1 contrast; for warnings on light backgrounds use `#7A5612` text on `#FDF6E9` fill -> 6.4:1 contrast)
  - `--astra-danger`: `#9E1C28` text on `#FDECEF` fill (6.8:1 contrast)
  - **Semantic Rule**: Never use color alone to convey status. Every status badge pairs an icon + explicit text label (`MATCHED (EXACT)`, `NEEDS REVIEW (SHORT-PAY)`, `QUARANTINED`, `POSTED (ACK)`).

---

## 3. Typography, Numerals & Data Density

- **Tabular Numerals Mandatory**: Every monetary amount, invoice number, confidence score, date, and control total uses `font-variant-numeric: tabular-nums` and monospace/tabular alignment.
- **Right-Aligned Amounts with Explicit Currency & Sign**:
  - Format currency according to ISO 4217 exponent (`USD 14,250.00`, `JPY 1,425,000`, `KWD 4,120.500`).
  - Never truncate or round amounts in allocation tables.
  - Mask sensitive bank account and virtual-card tokens by default (`ACCT •••• 4821`, `VCC-TOKEN •••• 9012`).

---

## 4. Unambiguous Financial Action UX & Maker-Checker Separation

- **"Review", "Approve", "Send", "Export", and "Post" are distinct actions** with distinct button styling, icons, and confirmation dialogs:
  - **Propose / Save Review (`Analyst`)**: Records candidate allocation and rationale; moves receipt to `approved_as_required` (if threshold requires controller sign-off) or `posting_pending` (if within auto/analyst policy).
  - **Approve Posting / Write-Off (`Controller`)**: Blocked if `current_user.id == preparer_user_id` (`SEC-09` Maker-Checker enforcement). Displays the exact preparer identity, policy rule triggered, and variance breakdown.
  - **Post to ERP / Export Batch**: Opens a mandatory **Dry-Run Pre-Flight Confirmation Modal** displaying:
    - Target ERP adapter (`SAP S/4HANA`, `Oracle Fusion`, `NetSuite`, `Odoo`, `Sage`, or `CSV Export`)
    - Accounting period & open/closed status
    - Control totals ($\text{Receipt Total} = \text{Applied Cash} + \text{Unapplied Cash}$, plus open AR deduction residual)
    - Idempotency key & immutable batch reference

---

## 5. Split-View Match Review & Keyboard Accessibility (WCAG 2.2 AA)

- **Side-by-Side Evidence Inspection**:
  - Left pane: Source remittance document/email/statement viewer with highlighted bounding boxes (`doc_id:page:bbox`), OCR raw vs. corrected field diff, and image quality score (DPI, skew, denoise status).
  - Right pane: Ranked open-AR candidate table, 10-agent execution trace, per-line allocation editor, live control-total equation bar, and Pinaka/short-pay deduction panel.
- **Full Keyboard Workflow**:
  - `j` / `k` or `ArrowDown` / `ArrowUp` to navigate queue rows
  - `Enter` to open Split-View Match Review
  - `e` to focus evidence span
  - `a` to trigger Propose/Approve dialog (when permitted by role)
  - Visible `2px solid #111D32` (`#DEC189` on dark shell) `:focus-visible` ring on every interactive element, plus `aria-live="polite"` status announcements.
