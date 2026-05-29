import type { Metadata } from "next";
import { Geist, Geist_Mono, Inter } from "next/font/google";
import "./globals.css";
import { cn } from "@/lib/utils";

const inter = Inter({ subsets: ["latin"], variable: "--font-sans" });

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "RBAT — Binary Analysis Toolkit & Reverse Engineering Dashboard",
  description:
    "RBAT is a professional reverse-engineering static analysis toolkit for identifying security vulnerabilities, packing signatures, code caves, and malicious heuristics in compiled binaries (ELF, PE, Mach-O).",
  keywords: [
    "binary analysis",
    "reverse engineering",
    "static analysis",
    "security audit",
    "malware heuristics",
    "YARA rules",
    "ELF parser",
    "PE parser",
    "Mach-O disassembler",
    "code cave detection",
  ],
  authors: [{ name: "RBAT Core Team" }],
  openGraph: {
    title: "RBAT — Binary Analysis Toolkit & Reverse Engineering Dashboard",
    description:
      "Perform high-performance static analysis and security auditing on compiled binaries directly from a secure web dashboard.",
    type: "website",
    locale: "en_US",
    siteName: "RBAT Toolkit",
  },
  twitter: {
    card: "summary_large_image",
    title: "RBAT — Binary Analysis Toolkit & Reverse Engineering Dashboard",
    description:
      "Perform high-performance static analysis and security auditing on compiled binaries.",
  },
  robots: {
    index: true,
    follow: true,
    nocache: true,
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      className={cn(
        "dark h-full",
        "antialiased",
        geistSans.variable,
        geistMono.variable,
        "font-sans",
        inter.variable,
      )}
    >
      <body className="min-h-full flex flex-col bg-rbat-bg">{children}</body>
    </html>
  );
}
