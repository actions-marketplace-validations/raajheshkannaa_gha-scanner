'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { Loader2 } from 'lucide-react';

export function ScanForm() {
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const router = useRouter();

  async function handleScan(e: React.FormEvent) {
    e.preventDefault();
    const trimmed = input.trim();
    if (!trimmed || loading) return;

    // Quick client-side validation
    const repoPattern = /^[a-zA-Z0-9._-]+\/[a-zA-Z0-9._-]+$/;
    const urlPattern = /^https?:\/\/github\.com\/[a-zA-Z0-9._-]+\/[a-zA-Z0-9._-]+/;
    if (!repoPattern.test(trimmed) && !urlPattern.test(trimmed)) {
      setError('Please enter a valid repository (owner/repo) or GitHub URL.');
      return;
    }

    setLoading(true);
    setError(null);

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 30_000);

    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repo: trimmed }),
        signal: controller.signal,
      });
      clearTimeout(timeoutId);

      const data = await res.json();

      if (!res.ok) {
        setError(data.error || 'Something went wrong');
        return;
      }

      // Encode results in URL hash (Unicode-safe) and navigate
      const encoded = btoa(unescape(encodeURIComponent(JSON.stringify(data))));
      router.push(`/scan#r=${encodeURIComponent(encoded)}`);
    } catch (err) {
      clearTimeout(timeoutId);
      if (err instanceof DOMException && err.name === 'AbortError') {
        setError('Scan timed out. The repository may be too large. Please try again.');
      } else {
        setError('Failed to connect. Please try again.');
      }
    } finally {
      setLoading(false);
    }
  }

  return (
    <form onSubmit={handleScan} className="space-y-3">
      <div className="flex flex-col sm:flex-row gap-2">
        <div className="flex-1 flex items-center bg-[#111] border border-[#333] rounded-lg px-3 focus-within:ring-2 focus-within:ring-[#22c55e] focus-within:border-transparent transition-colors">
          <span className="text-[#22c55e] mr-1.5 text-sm select-none">$</span>
          <span className="text-[#94a3b8] mr-1 text-sm select-none whitespace-nowrap">gha-scan</span>
          <span className="text-[#fbbf24] mr-2 text-sm select-none whitespace-nowrap">--repo</span>
          <input
            type="text"
            aria-label="GitHub repository (owner/repo or URL)"
            aria-describedby={error ? 'scan-error' : undefined}
            aria-invalid={!!error}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="owner/repo"
            className="flex-1 bg-transparent py-3 text-[#e2e8f0] placeholder-[#71717a] focus:outline-none font-mono text-sm"
            disabled={loading}
          />
        </div>
        <button
          type="submit"
          disabled={loading || !input.trim()}
          className="bg-[#052e16] text-[#22c55e] border border-[#166534] hover:bg-[#14532d] disabled:bg-[#111] disabled:text-[#71717a] disabled:border-[#1e1e1e] font-medium px-6 py-3 rounded-lg transition-colors flex items-center justify-center gap-2 w-full sm:w-auto text-sm"
        >
          {loading ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              scanning...
            </>
          ) : (
            'scan'
          )}
        </button>
      </div>
      {error && (
        <p id="scan-error" className="text-[#ef4444] text-sm" role="alert">{error}</p>
      )}
      <p className="text-xs text-[#71717a]">
        Works with any public GitHub repository. Try: kubernetes/kubernetes, facebook/react
      </p>
    </form>
  );
}
