import type { Metadata } from 'next';
import { JetBrains_Mono } from 'next/font/google';
import Link from 'next/link';
import './globals.css';

const jetbrainsMono = JetBrains_Mono({ subsets: ['latin'] });

export const metadata: Metadata = {
  title: 'GHA Scanner - GitHub Actions Security Scanner',
  description: 'Scan your GitHub Actions workflows for security vulnerabilities. Free, instant, and comprehensive.',
  metadataBase: new URL('https://scan.defensive.works'),
  openGraph: {
    title: 'GHA Scanner - GitHub Actions Security Scanner',
    description: 'Is your GitHub Actions pipeline secure? Scan now.',
    type: 'website',
    images: [
      {
        url: '/og-image.png',
        width: 1200,
        height: 627,
        alt: 'GHA Scanner - 25 Security Checks for GitHub Actions',
      },
    ],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'GHA Scanner - GitHub Actions Security Scanner',
    description: 'Is your GitHub Actions pipeline secure? Scan now.',
    images: ['/og-image.png'],
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className={`${jetbrainsMono.className} bg-[#080808] text-slate-100 min-h-screen flex flex-col`}>
        {/* Green gradient accent line */}
        <div className="h-[2px] bg-gradient-to-r from-green-500 via-emerald-400 to-green-500" />

        {/* Title bar */}
        <header className="bg-[#111]">
          <div className="max-w-6xl mx-auto px-4 py-3 flex items-center justify-between">
            <Link href="/" className="flex items-center gap-0">
              <span className="font-semibold text-[#f1f5f9]">defensive</span>
              <span className="text-[#22c55e] font-semibold">.</span>
              <span className="font-semibold text-[#f1f5f9]">works</span>
            </Link>
            <nav className="flex items-center gap-5 text-sm text-[#94a3b8]">
              <Link href="/scan" className="hover:text-[#22c55e] transition-colors">scan</Link>
              <Link href="/blog" className="hover:text-[#22c55e] transition-colors">docs</Link>
              <a href="https://github.com/raajheshkannaa/gha-scanner" target="_blank" rel="noopener noreferrer" className="hover:text-[#22c55e] transition-colors">github</a>
            </nav>
          </div>
        </header>

        <main className="flex-1">{children}</main>

        <footer className="mt-auto">
          <div className="max-w-6xl mx-auto px-4 py-6">
            <div className="text-[#27272a] text-center text-xs mb-3 select-none" aria-hidden="true">
              {'─'.repeat(60)}
            </div>
            <div className="flex items-center justify-between text-xs text-[#71717a]">
              <span>25 checks across 8 categories</span>
              <span>
                by{' '}
                <a href="https://raajhe.sh" target="_blank" rel="noopener noreferrer" className="text-[#94a3b8] hover:text-[#22c55e] transition-colors">
                  raajhesh
                </a>
                <span className="ml-1 inline-block" style={{ animation: 'blink 1s step-end infinite' }}>_</span>
              </span>
            </div>
          </div>
        </footer>
      </body>
    </html>
  );
}
