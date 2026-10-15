import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";

export const metadata: Metadata = {
  title: "OpenHookbin",
  description: "Webhook inspector with live console and request history"
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>
        <header className="site-shell">
          <div className="site-nav">
            <Link href="/" className="brand">
              OpenHookbin
            </Link>
          </div>
        </header>
        {children}
        <footer className="site-shell site-footer">
          <div className="footer-links">
            <Link href="./replication/collector" target="_blank" rel="noreferrer">
              GitHub
            </Link>
            <Link href="/privacy">Privacy</Link>
          </div>
        </footer>
      </body>
    </html>
  );
}
