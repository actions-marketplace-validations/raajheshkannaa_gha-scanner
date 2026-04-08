'use client';

import { useState } from 'react';
import { Finding } from '@/lib/scanner/types';
import { ChevronDown, ChevronRight } from 'lucide-react';

const severityStyles: Record<string, string> = {
  critical: 'text-[#ef4444] font-semibold',
  high: 'text-[#f97316] font-semibold',
  medium: 'text-[#eab308] font-semibold',
  low: 'text-[#22c55e] font-semibold',
  info: 'text-[#94a3b8]',
};

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={() => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 1500); }}
      className="absolute top-2 right-2 text-xs text-[#94a3b8] hover:text-[#cbd5e1] bg-[#111] px-1.5 py-0.5 rounded border border-[#1e1e1e]"
      aria-label="Copy to clipboard"
    >
      {copied ? 'Copied' : 'Copy'}
    </button>
  );
}

export function FindingCard({ finding }: { finding: Finding }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="px-4 py-3">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full text-left flex items-start gap-3 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#22c55e] rounded"
        aria-expanded={expanded}
        aria-label={`${finding.severity} finding: ${finding.title}`}
      >
        <span className={`text-xs px-0 py-0.5 mt-0.5 flex-shrink-0 uppercase tracking-wide min-w-[5rem] font-mono ${severityStyles[finding.severity]}`}>
          [{finding.severity}]
        </span>
        <div className="flex-1 min-w-0">
          <div className="font-medium text-sm text-[#e2e8f0]">{finding.title}</div>
          <div className="text-xs text-[#94a3b8] mt-0.5 font-mono">
            {finding.file}{finding.line ? `:${finding.line}` : ''}
          </div>
        </div>
        {expanded ? <ChevronDown className="w-4 h-4 text-[#94a3b8] mt-1" /> : <ChevronRight className="w-4 h-4 text-[#94a3b8] mt-1" />}
      </button>

      {expanded && (
        <div className="mt-3 ml-0 sm:ml-[5rem] space-y-3 text-sm">
          {/* Evidence */}
          <div>
            <div className="text-xs text-[#94a3b8] mb-1">Evidence</div>
            <pre className="bg-[#0a0a0a] border border-[#1e1e1e] rounded p-2 text-xs text-[#cbd5e1] overflow-x-auto whitespace-pre-wrap break-words">
              <code>{finding.evidence}</code>
            </pre>
          </div>

          {/* Risk */}
          <div>
            <div className="text-xs text-[#94a3b8] mb-1">Risk</div>
            <p className="text-[#cbd5e1]">{finding.risk}</p>
          </div>

          {/* Remediation */}
          <div>
            <div className="text-xs text-[#22c55e] mb-1">Remediation</div>
            <div className="relative">
              <CopyButton text={finding.remediation} />
              <pre className="bg-[#0a0a0a] border border-[#052e16] rounded p-2 pr-16 text-xs text-[#22c55e] overflow-x-auto whitespace-pre-wrap break-words">
                <code>{finding.remediation}</code>
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
