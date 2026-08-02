import type { Metadata } from "next";
import type { ReactNode } from "react";
import "./globals.css";
import { ThemeToggle } from "../components/theme-toggle";

export const metadata: Metadata = {
  title: "OneLayer — synthetic devnet demo",
  description: "Admin panel and public certificate verification for the OneLayer devnet MVP.",
};

export default function RootLayout({ children }: { children: ReactNode }): ReactNode {
  return (
    <html lang="en" data-theme="dark">
      <body>
        <div className="ol-banner">
          <strong>DEVNET SYNTHETIC DEMO — no real registry data</strong>
          <ThemeToggle />
        </div>
        {children}
      </body>
    </html>
  );
}
