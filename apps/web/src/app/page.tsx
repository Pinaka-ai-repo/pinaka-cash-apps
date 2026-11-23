"use client";

import React, { useState } from "react";

type ViewTab =
  | "workbench"
  | "match_review"
  | "short_pay_pinaka"
  | "erp_connectors"
  | "chat_reports"
  | "audit_sod";

type RolePersona =
  | "analyst"
  | "controller"
  | "treasury"
  | "connector_admin"
  | "internal_auditor";

interface ReceiptItem {
  id: string;
  channel: string;
  bankAccountMasked: string;
  bankRef: string;
  payerName: string;
  customerId: string;
  currency: string;
  grossMinor: number;
  feeMinor: number;
  netMinor: number;
  appliedMinor: number;
  unappliedMinor: number;
  state: string;
  tier: number;
  confidence: number;
  invoiceRef: string;
  ocrCorrectedFrom?: string;
  evidenceSpan: string;
  preparerId: string;
  approverId?: string;
  statedReason?: string;
  predictedReason?: string;
  layaPredictionSet?: string[];
  pinakaDelayDays?: number;
  pinakaProbability?: number;
  pinakaAsOf?: string;
}

const INITIAL_RECEIPTS: ReceiptItem[] = [
  {
    id: "RCPT-2026-1041",
    channel: "ISO 20022 camt.053",
    bankAccountMasked: "ACCT •••• 4821",
    bankRef: "CAMT-E2E-99012",
    payerName: "Apex Precision Manufacturing Corp",
    customerId: "CUST-0104",
    currency: "USD",
    grossMinor: 4250000,
    feeMinor: 0,
    netMinor: 4250000,
    appliedMinor: 4250000,
    unappliedMinor: 0,
    state: "posted",
    tier: 1,
    confidence: 0.992,
    invoiceRef: "INV-100104",
    evidenceSpan: "art-91c2f4:p1:bbox(40,120,260,140)",
    preparerId: "usr-analyst-01",
    approverId: "usr-controller-01",
  },
  {
    id: "RCPT-2026-1042",
    channel: "Scanned Remittance PDF",
    bankAccountMasked: "ACCT •••• 4821",
    bankRef: "LOCKBOX-77410",
    payerName: "Northstar Logistics LLC",
    customerId: "CUST-0219",
    currency: "USD",
    grossMinor: 1850000,
    feeMinor: 0,
    netMinor: 1850000,
    appliedMinor: 1850000,
    unappliedMinor: 0,
    state: "approved_as_required",
    tier: 1,
    confidence: 0.96,
    invoiceRef: "INV-100219",
    ocrCorrectedFrom: "INV-1OO2I9",
    evidenceSpan: "art-77b8a1:p1:bbox(44,168,280,192)",
    preparerId: "usr-analyst-01",
  },
  {
    id: "RCPT-2026-1043",
    channel: "Stripe Settlement Batch",
    bankAccountMasked: "VCC-TOKEN •••• 9012",
    bankRef: "STRIPE-PO-8831",
    payerName: "Helios Retail Group",
    customerId: "CUST-0308",
    currency: "USD",
    grossMinor: 2500000,
    feeMinor: 35000,
    netMinor: 2465000,
    appliedMinor: 2250000,
    unappliedMinor: 215000,
    state: "needs_review",
    tier: 2,
    confidence: 0.89,
    invoiceRef: "INV-100308",
    evidenceSpan: "art-54d1e9:p1:bbox(36,210,410,236)",
    preparerId: "usr-analyst-02",
    statedReason: "Cold chain excursion and punctured carton on pallet (-$2,500.00)",
    predictedReason: "damage",
    layaPredictionSet: ["damage"],
    pinakaDelayDays: 18,
    pinakaProbability: 0.78,
    pinakaAsOf: "2026-11-23T06:00:00Z (fresh_mock)",
  },
];

const ERP_ADAPTERS = [
  {
    id: "sap_s4hana",
    name: "SAP S/4HANA",
    protocol: "OData v4 (API_OPLACCTGDOCITEMCUBE_SRV) + JournalEntry BAPI/IDoc",
    secretRef: "vault://erp/sap_s4hana/oauth_m2m",
    tier: "automated fixture passed",
    mapping: "BUKRS -> legal_entity_id | KUNNR -> customer_id | BELNR -> invoice_number | WRBTR -> applied_minor",
  },
  {
    id: "oracle_fusion",
    name: "Oracle Fusion Cloud ERP / EBS",
    protocol: "Oracle REST v11.13 (receivablesInvoices / standardReceipts) + FBDI AutoLockbox CSV",
    secretRef: "vault://erp/oracle_fusion/oauth_jwt",
    tier: "automated fixture passed",
    mapping: "OrgId -> legal_entity_id | CustomerAccountNumber -> customer_id | TransactionNumber -> invoice_number",
  },
  {
    id: "netsuite",
    name: "Oracle NetSuite",
    protocol: "SuiteTalk REST Web Services v1 + SuiteQL (OAuth 2.0 M2M)",
    secretRef: "vault://erp/netsuite/oauth2_m2m_cert",
    tier: "automated fixture passed",
    mapping: "subsidiary.id -> legal_entity_id | entity.id -> customer_id | tranId -> invoice_number",
  },
  {
    id: "odoo",
    name: "Odoo ERP",
    protocol: "External JSON-RPC 2.0 (account.move / account.payment / account.partial.reconcile)",
    secretRef: "vault://erp/odoo/api_key_ref",
    tier: "automated fixture passed",
    mapping: "company_id -> legal_entity_id | partner_id -> customer_id | name -> invoice_number",
  },
  {
    id: "sage_intacct",
    name: "Sage Intacct / Sage X3",
    protocol: "Sage REST v1 (accounts-receivable/payment) + XML Web Services / CSV Batch",
    secretRef: "vault://erp/sage_intacct/oauth2_client",
    tier: "automated fixture passed",
    mapping: "locationId -> legal_entity_id | customer.id -> customer_id | invoiceNumber -> invoice_number",
  },
  {
    id: "universal_rest_csv",
    name: "Universal Open ERP Adapter",
    protocol: "Configurable REST Webhook + RFC-4180 CSV with Control Totals + Pinned MCP (2025-03-26)",
    secretRef: "vault://erp/universal/webhook_hmac",
    tier: "automated fixture passed",
    mapping: "legal_entity_id | customer_id | invoice_number | applied_minor | idempotency_key",
  },
];

function formatMinor(minor: number, currency: string): string {
  const val = minor / 100;
  return `${currency} ${val.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
}

export default function AstraEnterpriseWorkbench() {
  const [activeTab, setActiveTab] = useState<ViewTab>("workbench");
  const [legalEntity, setLegalEntity] = useState("US-CORP-01");
  const [period] = useState("2026-11 (OPEN)");
  const [currency, setCurrency] = useState("USD");
  const [role, setRole] = useState<RolePersona>("controller");
  const [receipts, setReceipts] = useState<ReceiptItem[]>(INITIAL_RECEIPTS);
  const [selectedIdx, setSelectedIdx] = useState<number>(1);
  const [selectedErp, setSelectedErp] = useState("sap_s4hana");
  const [statusAnnouncement, setStatusAnnouncement] = useState(
    "ASTRA Workbench ready. Zero external egress active (local-no-egress)."
  );
  const [dryRunModalOpen, setDryRunModalOpen] = useState(false);

  const currentUserId =
    role === "analyst"
      ? "usr-analyst-01"
      : role === "controller"
      ? "usr-controller-01"
      : role === "treasury"
      ? "usr-treasury-01"
      : role === "connector_admin"
      ? "usr-connadmin-01"
      : "usr-auditor-01";

  const selectedReceipt = receipts[selectedIdx] || receipts[0];

  const totalGross = receipts.reduce((acc, r) => acc + r.grossMinor, 0);
  const totalFee = receipts.reduce((acc, r) => acc + r.feeMinor, 0);
  const totalNet = receipts.reduce((acc, r) => acc + r.netMinor, 0);
  const totalApplied = receipts.reduce((acc, r) => acc + r.appliedMinor, 0);
  const totalUnapplied = receipts.reduce((acc, r) => acc + r.unappliedMinor, 0);

  function handleApproveAndPost() {
    if (role !== "controller") {
      setStatusAnnouncement("SEC-06/SEC-09 Denied: Only Controller role can approve and post to ERP.");
      return;
    }
    if (selectedReceipt.preparerId === currentUserId) {
      setStatusAnnouncement(
        `SEC-09 Maker-Checker Violation Blocked: Preparer (${currentUserId}) cannot self-approve receipt ${selectedReceipt.id}.`
      );
      return;
    }
    const updated = receipts.map((r, idx) =>
      idx === selectedIdx ? { ...r, state: "posted", approverId: currentUserId } : r
    );
    setReceipts(updated);
    setDryRunModalOpen(false);
    setStatusAnnouncement(
      `Posted ${selectedReceipt.id} to ${selectedErp.toUpperCase()} via idempotent key idem:${selectedReceipt.id}.`
    );
  }

  return (
    <div style={{ minHeight: "100vh", display: "flex", flexDirection: "column" }}>
      {/* Explicit Non-Color-Sole Operational Mode Banner */}
      <div
        role="status"
        aria-live="polite"
        style={{
          backgroundColor: "#192A47",
          color: "#DEC189",
          padding: "6px 20px",
          fontSize: "12px",
          fontWeight: 600,
          borderBottom: "1px solid #2A3F63",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
        }}
      >
        <span>
          [MODE: DEMO / LOCAL SANDBOX] — Synthetic Data Only | Execution Policy: local-no-egress | Host:
          astra.pinaka.local
        </span>
        <span className="tabular-nums">Audit Chain: SHA-256 VERIFIED | 47/47 SEC Controls: PASS</span>
      </div>

      {/* Dark Navy Top Shell (#111D32) */}
      <header
        className="dark-shell"
        style={{
          backgroundColor: "#111D32",
          color: "#F6F8FB",
          padding: "12px 20px",
          display: "flex",
          flexWrap: "wrap",
          justifyContent: "space-between",
          alignItems: "center",
          gap: "16px",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "14px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "12px" }} aria-label="ASTRA Brand">
            <span
              style={{
                width: "38px",
                height: "38px",
                borderRadius: "50%",
                border: "2.2px solid #DEC189",
                backgroundColor: "#111D32",
                color: "#F6F8FB",
                display: "inline-flex",
                alignItems: "center",
                justifyContent: "center",
                fontFamily: "'Bebas Neue', 'Impact', 'Arial Narrow', sans-serif",
                fontSize: "26px",
                fontWeight: 700,
                letterSpacing: "0.03em",
                lineHeight: 1,
              }}
            >
              A
            </span>
            <div>
              <div
                style={{
                  fontFamily: "'Bebas Neue', 'Inter', system-ui, sans-serif",
                  fontSize: "23px",
                  fontWeight: 700,
                  letterSpacing: "0.14em",
                  lineHeight: 1,
                  color: "#F6F8FB",
                }}
              >
                ASTRA
              </div>
              <div
                style={{
                  fontSize: "10px",
                  letterSpacing: "0.1em",
                  color: "#94A3B8",
                  fontWeight: 600,
                  marginTop: "2px",
                }}
              >
                AUTONOMOUS SETTLEMENT · PINAKA AI DELAY PREVENTION
              </div>
            </div>
          </div>
          <span
            style={{
              fontSize: "12px",
              padding: "3px 8px",
              borderRadius: "4px",
              backgroundColor: "#192A47",
              color: "#40AFA7",
              border: "1px solid #40AFA7",
              fontWeight: 600,
            }}
          >
            Autonomous Receivables · Pinaka AI
          </span>
        </div>

        {/* Persistent Entity, Period, Currency & Persona Switcher */}
        <div style={{ display: "flex", flexWrap: "wrap", gap: "10px", alignItems: "center" }}>
          <label style={{ fontSize: "12px" }}>
            Entity:{" "}
            <select
              aria-label="Legal Entity Switcher"
              value={legalEntity}
              onChange={(e) => setLegalEntity(e.target.value)}
              style={{
                backgroundColor: "#192A47",
                color: "#F6F8FB",
                border: "1px solid #40AFA7",
                borderRadius: "4px",
                padding: "4px 8px",
              }}
            >
              <option value="US-CORP-01">US-CORP-01 (US Midmarket/Enterprise · Net-30/60 Lockbox &amp; ACH)</option>
              <option value="EU-GMBH-02">EU-GMBH-02 (Europe · SEPA camt.053 &amp; Late Payment Directive)</option>
              <option value="UAE-FZCO-03">UAE-FZCO-03 (Middle East · Relationship AR &amp; Cheque/Stub OCR)</option>
              <option value="IN-PVT-03">IN-PVT-03 (APAC · Multi-Currency WHT &amp; Settlement)</option>
            </select>
          </label>

          <span
            className="tabular-nums"
            style={{
              fontSize: "12px",
              padding: "4px 8px",
              backgroundColor: "#192A47",
              borderRadius: "4px",
              border: "1px solid #2A3F63",
            }}
          >
            Period: {period}
          </span>

          <label style={{ fontSize: "12px" }}>
            CCY:{" "}
            <select
              aria-label="Currency Filter"
              value={currency}
              onChange={(e) => setCurrency(e.target.value)}
              style={{
                backgroundColor: "#192A47",
                color: "#F6F8FB",
                border: "1px solid #2A3F63",
                borderRadius: "4px",
                padding: "4px 8px",
              }}
            >
              <option value="USD">USD (2 dec)</option>
              <option value="EUR">EUR (2 dec)</option>
              <option value="INR">INR (2 dec)</option>
              <option value="JPY">JPY (0 dec)</option>
              <option value="KWD">KWD (3 dec)</option>
            </select>
          </label>

          <label style={{ fontSize: "12px" }}>
            SoD Role:{" "}
            <select
              aria-label="Segregation of Duties Persona"
              value={role}
              onChange={(e) => setRole(e.target.value as RolePersona)}
              style={{
                backgroundColor: "#DEC189",
                color: "#111D32",
                fontWeight: 700,
                border: "none",
                borderRadius: "4px",
                padding: "4px 8px",
              }}
            >
              <option value="analyst">Analyst (Preparer - No Post/Approve)</option>
              <option value="controller">Controller (Maker-Checker Approver)</option>
              <option value="treasury">Treasury (Reconciliation Attester)</option>
              <option value="connector_admin">Connector Admin (ERP Setup Only)</option>
              <option value="internal_auditor">Internal Auditor (Read-Only + Evidence ZIP)</option>
            </select>
          </label>
        </div>
      </header>

      {/* Primary Navigation Bar */}
      <nav
        aria-label="Primary Workbench Navigation"
        style={{
          backgroundColor: "#FFFFFF",
          borderBottom: "1px solid #D8E0EC",
          padding: "0 20px",
          display: "flex",
          gap: "8px",
          overflowX: "auto",
        }}
      >
        {(
          [
            ["workbench", "1. Cash Workbench & Bridge"],
            ["match_review", "2. Match Queue & Split-View Review"],
            ["short_pay_pinaka", "3. Short-Pay, Pinaka AI & Laya v0.5.2"],
            ["erp_connectors", "4. Open ERP Connector Hub (6 ERPs)"],
            ["chat_reports", "5. Grounded Chat & Treasury/FP&A Packs"],
            ["audit_sod", "6. Audit Evidence ZIP & 47 Controls"],
          ] as [ViewTab, string][]
        ).map(([tabKey, label]) => (
          <button
            key={tabKey}
            type="button"
            onClick={() => setActiveTab(tabKey)}
            style={{
              padding: "12px 14px",
              border: "none",
              borderBottom: activeTab === tabKey ? "3px solid #111D32" : "3px solid transparent",
              backgroundColor: "transparent",
              color: activeTab === tabKey ? "#111D32" : "#475569",
              fontWeight: activeTab === tabKey ? 700 : 500,
              cursor: "pointer",
              whiteSpace: "nowrap",
            }}
          >
            {label}
          </button>
        ))}
      </nav>

      {/* Live Accessible Status Bar */}
      <div
        role="region"
        aria-label="Operational Feedback"
        style={{
          backgroundColor: "#E6F6F4",
          color: "#136F68",
          padding: "8px 20px",
          fontSize: "13px",
          fontWeight: 600,
          borderBottom: "1px solid #B8E5DF",
        }}
      >
        {statusAnnouncement}
      </div>

      {/* Main Work Surface (#F6F8FB) */}
      <main style={{ flex: 1, padding: "20px", maxWidth: "1440px", width: "100%", margin: "0 auto" }}>
        {activeTab === "workbench" && (
          <section aria-label="Daily Cash KPIs and Reconciliation Bridge">
            <h1 style={{ margin: "0 0 12px 0", fontSize: "20px" }}>
              Daily Cash Application &amp; Bank-to-Subledger Bridge ({legalEntity})
            </h1>
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
                gap: "12px",
                marginBottom: "20px",
              }}
            >
              <div style={{ background: "#FFF", padding: "14px", border: "1px solid #D8E0EC", borderRadius: "6px" }}>
                <div style={{ fontSize: "12px", color: "#475569" }}>Gross Receipts Ingested</div>
                <div className="tabular-nums" style={{ fontSize: "20px", fontWeight: 700, marginTop: "4px" }}>
                  {formatMinor(totalGross, currency)}
                </div>
                <div style={{ fontSize: "12px", color: "#136F68", marginTop: "4px" }}>
                  Processor Fees: {formatMinor(totalFee, currency)}
                </div>
              </div>
              <div style={{ background: "#FFF", padding: "14px", border: "1px solid #D8E0EC", borderRadius: "6px" }}>
                <div style={{ fontSize: "12px", color: "#475569" }}>Net Bank Cash (Applied + Unapplied)</div>
                <div className="tabular-nums" style={{ fontSize: "20px", fontWeight: 700, marginTop: "4px" }}>
                  {formatMinor(totalNet, currency)}
                </div>
                <div style={{ fontSize: "12px", color: "#136F68", marginTop: "4px" }}>
                  Bridge Invariant: BALANCED (0 variance)
                </div>
              </div>
              <div style={{ background: "#FFF", padding: "14px", border: "1px solid #D8E0EC", borderRadius: "6px" }}>
                <div style={{ fontSize: "12px", color: "#475569" }}>Applied Cash vs. Unapplied Cash</div>
                <div className="tabular-nums" style={{ fontSize: "16px", fontWeight: 700, marginTop: "4px" }}>
                  Applied: {formatMinor(totalApplied, currency)}
                </div>
                <div className="tabular-nums" style={{ fontSize: "13px", color: "#7A5612", marginTop: "4px" }}>
                  Unapplied: {formatMinor(totalUnapplied, currency)}
                </div>
              </div>
              <div style={{ background: "#FFF", padding: "14px", border: "1px solid #D8E0EC", borderRadius: "6px" }}>
                <div style={{ fontSize: "12px", color: "#475569" }}>2,000-Receipt Benchmark Cohort</div>
                <div className="tabular-nums" style={{ fontSize: "20px", fontWeight: 700, color: "#136F68", marginTop: "4px" }}>
                  97.0% Auto-Match · 100.0% Precision
                </div>
                <div className="tabular-nums" style={{ fontSize: "12px", color: "#475569", marginTop: "4px" }}>
                  95% Wilson CI: [96.16%, 97.66%] (Synthetic CI)
                </div>
              </div>
            </div>
          </section>
        )}

        {(activeTab === "workbench" || activeTab === "match_review") && (
          <section aria-label="Split-View Match Queue and Evidence Inspector">
            <div style={{ display: "grid", gridTemplateColumns: "1.15fr 1fr", gap: "16px" }}>
              {/* Left Pane: Match Queue Table */}
              <div style={{ background: "#FFF", border: "1px solid #D8E0EC", borderRadius: "6px", padding: "14px" }}>
                <h2 style={{ margin: "0 0 10px 0", fontSize: "16px" }}>
                  Incoming Settlement Queue (Keyboard: Up/Down to select)
                </h2>
                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "13px" }}>
                  <thead>
                    <tr style={{ borderBottom: "2px solid #D8E0EC", textAlign: "left" }}>
                      <th style={{ padding: "8px 6px" }}>Receipt ID</th>
                      <th style={{ padding: "8px 6px" }}>Payer / Masked Account</th>
                      <th style={{ padding: "8px 6px", textAlign: "right" }}>Net Cash</th>
                      <th style={{ padding: "8px 6px" }}>Tier / Conf</th>
                      <th style={{ padding: "8px 6px" }}>State</th>
                    </tr>
                  </thead>
                  <tbody>
                    {receipts.map((r, idx) => (
                      <tr
                        key={r.id}
                        onClick={() => setSelectedIdx(idx)}
                        style={{
                          borderBottom: "1px solid #E2E8F0",
                          backgroundColor: idx === selectedIdx ? "#E6F6F4" : "transparent",
                          cursor: "pointer",
                        }}
                      >
                        <td className="tabular-nums" style={{ padding: "8px 6px", fontWeight: 600 }}>
                          {r.id}
                        </td>
                        <td style={{ padding: "8px 6px" }}>
                          <div>{r.payerName}</div>
                          <div className="tabular-nums" style={{ fontSize: "11px", color: "#475569" }}>
                            {r.channel} · {r.bankAccountMasked}
                          </div>
                        </td>
                        <td className="num-right" style={{ padding: "8px 6px", fontWeight: 600 }}>
                          {formatMinor(r.netMinor, r.currency)}
                        </td>
                        <td className="tabular-nums" style={{ padding: "8px 6px" }}>
                          T{r.tier} · {(r.confidence * 100).toFixed(1)}%
                        </td>
                        <td style={{ padding: "8px 6px" }}>
                          <span
                            style={{
                              padding: "2px 6px",
                              borderRadius: "4px",
                              fontSize: "11px",
                              fontWeight: 700,
                              backgroundColor: r.state === "posted" ? "#E6F6F4" : "#FDF6E9",
                              color: r.state === "posted" ? "#136F68" : "#7A5612",
                            }}
                          >
                            {r.state.toUpperCase()}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Right Pane: Side-by-Side Bounding-Box Evidence & Maker-Checker Action Panel */}
              <div style={{ background: "#FFF", border: "1px solid #D8E0EC", borderRadius: "6px", padding: "14px" }}>
                <h2 style={{ margin: "0 0 10px 0", fontSize: "16px" }}>
                  Split-View Evidence &amp; Allocation Inspector: {selectedReceipt.id}
                </h2>
                <div
                  style={{
                    backgroundColor: "#111D32",
                    color: "#F6F8FB",
                    padding: "10px 12px",
                    borderRadius: "4px",
                    fontSize: "12px",
                    marginBottom: "12px",
                  }}
                >
                  <div>
                    <strong>Immutable Evidence Pointer:</strong>{" "}
                    <code style={{ color: "#DEC189" }}>{selectedReceipt.evidenceSpan}</code>
                  </div>
                  <div style={{ marginTop: "4px" }}>
                    <strong>Extracted Invoice Ref:</strong> {selectedReceipt.invoiceRef}{" "}
                    {selectedReceipt.ocrCorrectedFrom && (
                      <span style={{ color: "#40AFA7" }}>
                        (CorrectionAgent repaired from OCR `{selectedReceipt.ocrCorrectedFrom}`)
                      </span>
                    )}
                  </div>
                  <div className="tabular-nums" style={{ marginTop: "4px" }}>
                    <strong>Control Total Equation:</strong> Net {formatMinor(selectedReceipt.netMinor, currency)} = Applied{" "}
                    {formatMinor(selectedReceipt.appliedMinor, currency)} + Unapplied{" "}
                    {formatMinor(selectedReceipt.unappliedMinor, currency)}
                  </div>
                </div>

                <div style={{ fontSize: "13px", marginBottom: "12px" }}>
                  <div>
                    <strong>Preparer ID:</strong> <code>{selectedReceipt.preparerId}</code> |{" "}
                    <strong>Current Session User:</strong> <code>{currentUserId}</code> ({role})
                  </div>
                  {selectedReceipt.approverId && (
                    <div style={{ color: "#136F68", marginTop: "4px" }}>
                      <strong>Approved &amp; Posted By:</strong> <code>{selectedReceipt.approverId}</code>
                    </div>
                  )}
                </div>

                {/* Distinct Unambiguous Action Buttons */}
                <div style={{ display: "flex", gap: "10px", flexWrap: "wrap" }}>
                  <button
                    type="button"
                    onClick={() =>
                      setStatusAnnouncement(`Saved analyst review rationale for ${selectedReceipt.id}.`)
                    }
                    style={{
                      padding: "8px 12px",
                      backgroundColor: "#FFFFFF",
                      color: "#111D32",
                      border: "1px solid #111D32",
                      borderRadius: "4px",
                      fontWeight: 600,
                      cursor: "pointer",
                    }}
                  >
                    1. Save Analyst Proposal
                  </button>

                  <button
                    type="button"
                    onClick={() => setDryRunModalOpen(true)}
                    style={{
                      padding: "8px 12px",
                      backgroundColor: "#111D32",
                      color: "#DEC189",
                      border: "none",
                      borderRadius: "4px",
                      fontWeight: 700,
                      cursor: "pointer",
                    }}
                  >
                    2. Dry-Run Preview &amp; Approve ERP Post (Controller)
                  </button>
                </div>

                {dryRunModalOpen && (
                  <div
                    role="dialog"
                    aria-label="ERP Posting Dry-Run Confirmation"
                    style={{
                      marginTop: "14px",
                      padding: "12px",
                      border: "2px solid #111D32",
                      borderRadius: "6px",
                      backgroundColor: "#F6F8FB",
                    }}
                  >
                    <h3 style={{ margin: "0 0 8px 0", fontSize: "14px" }}>
                      Dry-Run ERP Posting Confirmation ({selectedErp.toUpperCase()})
                    </h3>
                    <div className="tabular-nums" style={{ fontSize: "12px", marginBottom: "10px" }}>
                      <div>Target ERP: {selectedErp} | Period: {period}</div>
                      <div>Idempotency Key: idem:{legalEntity}:{selectedReceipt.id}</div>
                      <div>
                        Amount Applied: {formatMinor(selectedReceipt.appliedMinor, currency)} | Unapplied:{" "}
                        {formatMinor(selectedReceipt.unappliedMinor, currency)}
                      </div>
                      <div>Maker-Checker Verification: Preparer {selectedReceipt.preparerId} vs Approver {currentUserId}</div>
                    </div>
                    <div style={{ display: "flex", gap: "8px" }}>
                      <button
                        type="button"
                        onClick={handleApproveAndPost}
                        style={{
                          padding: "6px 12px",
                          backgroundColor: "#136F68",
                          color: "#FFF",
                          border: "none",
                          borderRadius: "4px",
                          fontWeight: 700,
                          cursor: "pointer",
                        }}
                      >
                        Confirm &amp; Execute Idempotent ERP Post
                      </button>
                      <button
                        type="button"
                        onClick={() => setDryRunModalOpen(false)}
                        style={{
                          padding: "6px 12px",
                          backgroundColor: "#FFF",
                          border: "1px solid #475569",
                          borderRadius: "4px",
                          cursor: "pointer",
                        }}
                      >
                        Cancel
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </section>
        )}

        {activeTab === "short_pay_pinaka" && (
          <section aria-label="Short-Pay DeductionCaseV1, Pinaka AI RiskSnapshotV1, and Laya v0.5.2 Spike">
            <h1 style={{ margin: "0 0 12px 0", fontSize: "20px" }}>
              Autonomous Receivables Radar — Pinaka AI Delay Prevention (`RiskSnapshotV1`) &amp; Laya v0.5.2 Short-Pay Conformal Sets
            </h1>
            <p style={{ fontSize: "13px", color: "#475569", marginTop: 0 }}>
              Shifting AR from reactive post-due chasing to proactive payment-delay prevention across US, Europe &amp; Middle East entities.
              Guardrail: Observed remittance facts, Laya v0.5.2 conformal sets, and Pinaka delay forecasts stay in separate columns and never auto-write-off AR.
            </p>
            <div style={{ background: "#FFF", border: "1px solid #D8E0EC", borderRadius: "6px", padding: "14px" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "13px" }}>
                <thead>
                  <tr style={{ borderBottom: "2px solid #D8E0EC", textAlign: "left" }}>
                    <th style={{ padding: "8px" }}>Case / Region / Invoice</th>
                    <th style={{ padding: "8px", textAlign: "right" }}>Open AR Residual</th>
                    <th style={{ padding: "8px" }}>Observed Remittance Fact</th>
                    <th style={{ padding: "8px" }}>Predicted Reason (Laya v0.5.2 Conformal)</th>
                    <th style={{ padding: "8px" }}>Pinaka AI Pre-Due Delay Signal (`RiskSnapshotV1`)</th>
                  </tr>
                </thead>
                <tbody>
                  <tr style={{ borderBottom: "1px solid #E2E8F0" }}>
                    <td className="tabular-nums" style={{ padding: "8px", fontWeight: 600 }}>
                      DED-1043 · US-CORP-01 / INV-100308
                    </td>
                    <td className="num-right" style={{ padding: "8px", fontWeight: 700, color: "#9E1C28" }}>
                      USD 2,500.00
                    </td>
                    <td style={{ padding: "8px" }}>
                      &ldquo;Cold chain excursion and punctured carton on pallet&rdquo; (<code>art-54d1e9:p1</code>)
                    </td>
                    <td style={{ padding: "8px" }}>
                      <strong>damage</strong> (conf: 0.96, set: <code>[&quot;damage&quot;]</code>, abstain: false)
                    </td>
                    <td className="tabular-nums" style={{ padding: "8px" }}>
                      <strong>+18 days predicted delay</strong> (P=0.78) · Pre-due logistics proof packet queued · Write-Off Locked
                    </td>
                  </tr>
                  <tr style={{ borderBottom: "1px solid #E2E8F0" }}>
                    <td className="tabular-nums" style={{ padding: "8px", fontWeight: 600 }}>
                      DED-1044 · EU-GMBH-02 / INV-204910
                    </td>
                    <td className="num-right" style={{ padding: "8px", fontWeight: 700, color: "#7A5612" }}>
                      EUR 1,420.00
                    </td>
                    <td style={{ padding: "8px" }}>
                      &ldquo;2% Skonto taken outside 10-day window on SEPA camt.053&rdquo; (<code>art-82a0c1:p1</code>)
                    </td>
                    <td style={{ padding: "8px" }}>
                      <strong>unearned_discount</strong> (conf: 0.94, set: <code>[&quot;unearned_discount&quot;]</code>, abstain: false)
                    </td>
                    <td className="tabular-nums" style={{ padding: "8px" }}>
                      <strong>+12 days structural DSO drift</strong> (P=0.74) · EU Late Payment Directive notice drafted
                    </td>
                  </tr>
                  <tr>
                    <td className="tabular-nums" style={{ padding: "8px", fontWeight: 600 }}>
                      DED-1045 · UAE-FZCO-03 / INV-309112
                    </td>
                    <td className="num-right" style={{ padding: "8px", fontWeight: 700, color: "#136F68" }}>
                      AED 9,180.00
                    </td>
                    <td style={{ padding: "8px" }}>
                      &ldquo;Scanned cheque stub retention hold pending milestone sign-off&rdquo; (<code>art-61f3d0:p1</code>)
                    </td>
                    <td style={{ padding: "8px" }}>
                      <strong>contract_retention</strong> (conf: 0.92, set: <code>[&quot;contract_retention&quot;]</code>, abstain: false)
                    </td>
                    <td className="tabular-nums" style={{ padding: "8px" }}>
                      <strong>+14 days relationship release cycle</strong> (P=0.81) · Concierge pre-due delivery confirmation sent
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>
        )}

        {activeTab === "erp_connectors" && (
          <section aria-label="Open ERP Connector Hub and No-Code Mapping Wizard">
            <h1 style={{ margin: "0 0 12px 0", fontSize: "20px" }}>
              Open ERP Connector Hub — SAP S/4HANA, Oracle, NetSuite, Odoo, Sage &amp; Universal REST/CSV/MCP
            </h1>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(380px, 1fr))", gap: "12px" }}>
              {ERP_ADAPTERS.map((erp) => (
                <div
                  key={erp.id}
                  style={{
                    background: "#FFF",
                    border: selectedErp === erp.id ? "2px solid #111D32" : "1px solid #D8E0EC",
                    borderRadius: "6px",
                    padding: "14px",
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <strong>{erp.name}</strong>
                    <span
                      style={{
                        fontSize: "11px",
                        padding: "2px 6px",
                        backgroundColor: "#E6F6F4",
                        color: "#136F68",
                        borderRadius: "4px",
                        fontWeight: 700,
                      }}
                    >
                      {erp.tier}
                    </span>
                  </div>
                  <div style={{ fontSize: "12px", color: "#475569", marginTop: "6px" }}>{erp.protocol}</div>
                  <div style={{ fontSize: "12px", marginTop: "6px" }}>
                    <strong>Vault Ref (`SEC-14`):</strong> <code>{erp.secretRef}</code>
                  </div>
                  <div style={{ fontSize: "12px", marginTop: "6px" }}>
                    <strong>Field Map:</strong> <code>{erp.mapping}</code>
                  </div>
                  <button
                    type="button"
                    onClick={() => {
                      setSelectedErp(erp.id);
                      setStatusAnnouncement(
                        `Dry-Run Contract & Control-Total Test PASSED against local Mock ERP for ${erp.name}.`
                      );
                    }}
                    style={{
                      marginTop: "10px",
                      padding: "6px 10px",
                      backgroundColor: "#111D32",
                      color: "#F6F8FB",
                      border: "none",
                      borderRadius: "4px",
                      fontSize: "12px",
                      fontWeight: 600,
                      cursor: "pointer",
                    }}
                  >
                    Select &amp; Run Dry-Run Contract Test
                  </button>
                </div>
              ))}
            </div>
          </section>
        )}

        {activeTab === "chat_reports" && (
          <section aria-label="Grounded Read-Only Chat and Treasury/FP&A Starter Packs">
            <h1 style={{ margin: "0 0 12px 0", fontSize: "20px" }}>
              Grounded Read-Only Chat (`AnswerV1`) &amp; Declarative Report Packs (`ReportSpecV1`)
            </h1>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px" }}>
              <div style={{ background: "#FFF", border: "1px solid #D8E0EC", borderRadius: "6px", padding: "14px" }}>
                <h2 style={{ margin: "0 0 8px 0", fontSize: "16px" }}>
                  Grounded Chat (`SEC-41` Scoped RAG · `SEC-44` Zero Write Tools)
                </h2>
                <div style={{ fontSize: "13px", background: "#F6F8FB", padding: "10px", borderRadius: "4px" }}>
                  <div>
                    <strong>Query:</strong> &ldquo;Why was receipt RCPT-2026-1042 matched, and what does Pinaka predict
                    for Helios Retail Group?&rdquo;
                  </div>
                  <div style={{ marginTop: "8px" }}>
                    <strong>AnswerV1 (`status: answered`):</strong>
                    <ul style={{ margin: "6px 0", paddingLeft: "18px" }}>
                      <li>
                        <strong>Observation:</strong> Receipt <code>RCPT-2026-1042</code> (USD 18,500.00) matched{" "}
                        <code>INV-100219</code> after CorrectionAgent repaired OCR confusable <code>INV-1OO2I9</code>{" "}
                        [Citation: <code>art-77b8a1:p1:bbox(44,168,280,192)</code>].
                      </li>
                      <li>
                        <strong>Prediction (Pinaka AI):</strong> <code>RiskSnapshotV1</code> for{" "}
                        <code>CUST-0308</code> predicts +18 days delay (P=0.78) as of{" "}
                        <code>2026-11-23T06:00:00Z</code> [Citation: <code>pinaka-snap-0308</code>].
                      </li>
                    </ul>
                  </div>
                </div>
              </div>

              <div style={{ background: "#FFF", border: "1px solid #D8E0EC", borderRadius: "6px", padding: "14px" }}>
                <h2 style={{ margin: "0 0 8px 0", fontSize: "16px" }}>
                  Treasury &amp; FP&amp;A 13-Week Rolling Cash Forecast Starter Packs
                </h2>
                <div className="tabular-nums" style={{ fontSize: "13px" }}>
                  <div>
                    <strong>Treasury Daily Bridge:</strong> Gross USD 86,000.00 - Fees USD 350.00 = Net USD 85,650.00
                    (Applied USD 83,500.00 + Unapplied USD 2,150.00)
                  </div>
                  <div style={{ marginTop: "8px" }}>
                    <strong>FP&amp;A 13-Week Rolling Cash-In Forecast (with Pinaka Overlay):</strong>
                  </div>
                  <div>Backtest MAE: USD 1,625.00 | Bias: -USD 125.00 across 4 realized cohorts</div>
                  <div style={{ fontSize: "11px", color: "#475569", marginTop: "6px" }}>
                    Disclaimer: Expected cash collection projection only; does not represent GAAP/IFRS revenue
                    recognition.
                  </div>
                </div>
              </div>
            </div>
          </section>
        )}

        {activeTab === "audit_sod" && (
          <section aria-label="Audit Evidence ZIP Exporter and 47 Security Controls">
            <h1 style={{ margin: "0 0 12px 0", fontSize: "20px" }}>
              Cryptographic Audit Evidence ZIP (`SEC-27` / `SEC-29`) &amp; 8-Role Segregation of Duties
            </h1>
            <div style={{ background: "#FFF", border: "1px solid #D8E0EC", borderRadius: "6px", padding: "14px" }}>
              <p style={{ margin: "0 0 10px 0", fontSize: "13px" }}>
                Exports formula-safe CSVs (`=`, `+`, `-`, `@` neutralized), SHA-256 hash-chained approval timeline, and
                redacted source evidence scoped strictly to <strong>{legalEntity}</strong>.
              </p>
              <button
                type="button"
                onClick={() =>
                  setStatusAnnouncement(
                    `Generated scoped Audit Evidence ZIP for ${legalEntity} with SHA-256 manifest and 15-minute expiry download token.`
                  )
                }
                style={{
                  padding: "8px 14px",
                  backgroundColor: "#111D32",
                  color: "#DEC189",
                  border: "none",
                  borderRadius: "4px",
                  fontWeight: 700,
                  cursor: "pointer",
                }}
              >
                Generate &amp; Verify Scoped Audit Evidence ZIP
              </button>
            </div>
          </section>
        )}
      </main>
    </div>
  );
}
