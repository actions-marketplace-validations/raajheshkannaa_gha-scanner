import type { Metadata } from 'next';
import { Inter } from 'next/font/google';
import Link from 'next/link';
import './globals.css';

const inter = Inter({ subsets: ['latin'] });

export const metadata: Metadata = {
  title: 'GHA Scanner - GitHub Actions Security Scanner',
  description: 'Scan your GitHub Actions workflows for security vulnerabilities. Free, instant, and comprehensive.',
  openGraph: {
    title: 'GHA Scanner - GitHub Actions Security Scanner',
    description: 'Is your GitHub Actions pipeline secure? Scan now.',
    type: 'website',
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className={`${inter.className} bg-slate-950 text-slate-100 min-h-screen flex flex-col`}>
        <header className="border-b border-slate-800">
          <div className="max-w-5xl mx-auto px-4 py-4 flex items-center justify-between">
            <Link href="/" className="flex items-center gap-2">
              <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-emerald-400"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/></svg>
              <span className="font-semibold text-lg">GHA Scanner</span>
            </Link>
            <nav className="text-sm text-slate-400">
              <a href="https://github.com/raajheshkannaa/gha-scanner" target="_blank" rel="noopener noreferrer" className="hover:text-slate-300 transition-colors">GitHub</a>
            </nav>
          </div>
        </header>
        <main className="flex-1">{children}</main>
        <footer className="border-t border-slate-800 mt-auto">
          <div className="max-w-5xl mx-auto px-4 py-6 text-center text-sm text-slate-500">
            Open source GitHub Actions security scanner. Built by practitioners.
          </div>
        </footer>
      </body>
    </html>
  );
}
