import type { ReactNode } from "react";
import "./globals.css";

export const metadata = {
  title: "ASTRA | Autonomous Settlement, Tracking & Reconciliation Architecture",
  description: "Self-hosted MIT-licensed Enterprise Cash Application & ERP Reconciliation Workbench by Pinaka AI",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
