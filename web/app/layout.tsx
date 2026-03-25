import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Shipwryte Scan — Free security scanner for AI-generated code",
  description:
    "Your AI app works. Find out if it's secure. Scan for hardcoded secrets, vulnerable dependencies, and injection flaws in 60 seconds.",
  openGraph: {
    title: "Shipwryte Scan",
    description:
      "Free security scanner for AI-generated code. Built for Cursor, Lovable, Bolt, and Claude projects.",
    type: "website",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="min-h-screen flex flex-col">{children}</body>
    </html>
  );
}
