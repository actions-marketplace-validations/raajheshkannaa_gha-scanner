import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        background: "var(--background)",
        foreground: "var(--foreground)",
        card: '#0a0a0a',
        terminal: {
          green: '#22c55e',
          blue: '#38bdf8',
          yellow: '#fbbf24',
          red: '#ef4444',
          orange: '#f97316',
          muted: '#475569',
          faint: '#3f3f46',
          border: '#1e1e1e',
          surface: '#111111',
        },
      },
    },
  },
  plugins: [],
};
export default config;
