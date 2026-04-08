import { ScanForm } from '@/components/scanner/ScanForm';

const categories = [
  { tag: 'supply-chain', name: 'Supply Chain', desc: 'Unpinned actions, mutable tags, known CVEs', color: 'text-[#ef4444]' },
  { tag: 'injection', name: 'Injection', desc: 'Expression injection in run blocks', color: 'text-[#f97316]' },
  { tag: 'triggers', name: 'Dangerous Triggers', desc: 'pull_request_target misuse', color: 'text-[#fbbf24]' },
  { tag: 'permissions', name: 'Permissions', desc: 'Overly broad GITHUB_TOKEN scope', color: 'text-[#38bdf8]' },
  { tag: 'secrets', name: 'Secrets Exposure', desc: 'Leaked secrets in logs and artifacts', color: 'text-purple-400' },
  { tag: 'runner', name: 'Runner Security', desc: 'Self-hosted runner risks', color: 'text-pink-400' },
  { tag: 'hygiene', name: 'CI/CD Hygiene', desc: 'Timeouts, concurrency, error handling', color: 'text-cyan-400' },
  { tag: 'best-practices', name: 'Best Practices', desc: 'Dependabot, CODEOWNERS', color: 'text-[#22c55e]' },
];

export default function Home() {
  return (
    <div className="max-w-5xl mx-auto px-4 py-16">
      {/* Hero */}
      <div className="mb-12">
        <div className="mb-6">
          <p className="text-[#94a3b8] mb-2">
            <span className="text-[#22c55e]">$</span> gha-scan <span className="text-[#fbbf24]">--help</span>
          </p>
          <p className="text-[#cbd5e1] text-lg">
            Scan any public GitHub Actions repository for security vulnerabilities.
          </p>
          <p className="text-[#94a3b8] mt-1">
            25 checks across 8 categories. Free, instant, no sign-up.
          </p>
        </div>
      </div>

      {/* Scan Form */}
      <div className="max-w-3xl mb-16">
        <ScanForm />
      </div>

      {/* What We Check */}
      <div className="mb-16">
        <h2 className="text-lg font-semibold text-[#cbd5e1] mb-6">
          <span className="text-[#94a3b8]">#</span> categories
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
          {categories.map((cat) => (
            <div
              key={cat.name}
              className="bg-[#0a0a0a] border border-[#1e1e1e] rounded-lg p-4 hover:border-[#333] transition-colors"
            >
              <div className={`text-xs font-mono ${cat.color} mb-2`}>[{cat.tag}]</div>
              <h3 className="font-medium text-sm text-[#e2e8f0] mb-1">{cat.name}</h3>
              <p className="text-xs text-[#94a3b8]">{cat.desc}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Trust indicators */}
      <div className="text-xs text-[#71717a]">
        <p>25 checks inspired by real attacks: tj-actions (2025), Trivy (2026), Shai Hulud, GhostAction</p>
        <p className="mt-1">No data stored. No sign-up. Open source scanner engine.</p>
      </div>
    </div>
  );
}
