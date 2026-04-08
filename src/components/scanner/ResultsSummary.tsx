'use client';

import { ScanResult } from '@/lib/scanner/types';

const gradeColors: Record<string, string> = {
  A: 'text-[#22c55e] border-[#22c55e]',
  B: 'text-[#22c55e] border-[#22c55e]',
  C: 'text-[#fbbf24] border-[#fbbf24]',
  D: 'text-[#f97316] border-[#f97316]',
  F: 'text-[#ef4444] border-[#ef4444]',
};

const gradeBg: Record<string, string> = {
  A: 'bg-[#052e16]',
  B: 'bg-[#052e16]',
  C: 'bg-[#422006]',
  D: 'bg-[#431407]',
  F: 'bg-[#7f1d1d]',
};

export function ResultsSummary({ result }: { result: ScanResult }) {
  const color = gradeColors[result.grade] || gradeColors.F;
  const bg = gradeBg[result.grade] || gradeBg.F;
  const criticalCount = result.findings.filter(f => f.severity === 'critical').length;
  const highCount = result.findings.filter(f => f.severity === 'high').length;
  const mediumCount = result.findings.filter(f => f.severity === 'medium').length;
  const lowCount = result.findings.filter(f => f.severity === 'low').length;

  return (
    <div className="bg-[#0a0a0a] border border-[#1e1e1e] rounded-xl p-6">
      <div className="flex flex-col sm:flex-row items-center gap-6 sm:gap-8">
        {/* Grade circle */}
        <div className={`w-24 h-24 rounded-full border-4 ${color} ${bg} flex items-center justify-center flex-shrink-0`}>
          <div className="text-center">
            <div className={`text-3xl font-bold ${color.split(' ')[0]}`}>{result.grade}</div>
            <div className="text-xs text-[#94a3b8]">{result.score}/100</div>
          </div>
        </div>

        {/* Stats */}
        <div className="flex-1 text-center sm:text-left">
          <div className="flex items-baseline justify-center sm:justify-start gap-2 mb-2">
            <span className="text-lg font-semibold text-[#e2e8f0]">{result.passingChecks}</span>
            <span className="text-[#94a3b8]">of {result.totalChecks} checks passed</span>
          </div>
          <div className="flex flex-wrap justify-center sm:justify-start gap-3 text-sm">
            {criticalCount > 0 && (
              <span className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-[#ef4444]" aria-hidden="true" />
                <span className="text-[#ef4444]">{criticalCount} critical</span>
              </span>
            )}
            {highCount > 0 && (
              <span className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-[#f97316]" aria-hidden="true" />
                <span className="text-[#f97316]">{highCount} high</span>
              </span>
            )}
            {mediumCount > 0 && (
              <span className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-[#eab308]" aria-hidden="true" />
                <span className="text-[#eab308]">{mediumCount} medium</span>
              </span>
            )}
            {lowCount > 0 && (
              <span className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-[#22c55e]" aria-hidden="true" />
                <span className="text-[#22c55e]">{lowCount} low</span>
              </span>
            )}
            {result.findings.length === 0 && (
              <span className="text-[#22c55e]">No findings. Clean bill of health!</span>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
