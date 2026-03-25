# @shipwryte/scan

Free security scanner for AI-generated code. Catch surface-level vulnerabilities in 60 seconds.

Built for code from Cursor, Lovable, Bolt, ChatGPT, and other AI tools that ship fast but skip security.

## What it checks

- **Hardcoded secrets** — API keys, tokens, database credentials, private keys
- **Dependency vulnerabilities** — known CVEs, unpinned versions, risky git dependencies
- **Static analysis (SAST)** — SQL injection, XSS, command injection, eval, weak JWT, missing security headers, and more

## Quick start

```bash
npx @shipwryte/scan .
```

Or install globally:

```bash
npm install -g @shipwryte/scan
shipwryte-scan ./my-project
```

## Usage

```
shipwryte-scan [path] [options]

Options:
  -o, --output <format>   Output format: markdown, json, html (default: "markdown")
  -f, --file <path>       Output file path (default: shipwryte-report.{ext})
  --no-secrets            Skip secret detection
  --no-deps               Skip dependency scanning
  --no-sast               Skip static analysis
  --severity <level>      Minimum severity: low, medium, high, critical (default: "low")
  --json                  Output raw JSON to stdout
  -q, --quiet             Suppress progress output
  -V, --version           Output version number
  -h, --help              Display help
```

## Output formats

**Markdown** (default) — drop into your PR or README

```bash
shipwryte-scan ./my-app
```

**HTML** — shareable dark-themed report with score, grade, and findings

```bash
shipwryte-scan ./my-app -o html
```

**JSON** — pipe into CI or other tools

```bash
shipwryte-scan ./my-app --json
```

## How scoring works

Every scan produces a score from 0 to 100:

| Severity | Penalty |
|----------|---------|
| Critical | -15 pts |
| High     | -8 pts  |
| Medium   | -3 pts  |
| Low      | -1 pt   |

| Score   | Grade |
|---------|-------|
| 90-100  | A+    |
| 80-89   | A     |
| 70-79   | B     |
| 60-69   | C     |
| 50-59   | D     |
| 0-49    | F     |

## Enhanced scanning

If you have these tools installed, the scanner will use them automatically for deeper analysis:

- [Semgrep](https://semgrep.dev) — advanced SAST with custom AI-code rules
- [TruffleHog](https://github.com/trufflesecurity/trufflehog) — deep secret detection including git history
- [Trivy](https://trivy.dev) — comprehensive dependency vulnerability scanning

Without them, the built-in scanners still catch the most common issues.

## What it doesn't cover

Automated scans catch surface-level issues. They can't check:

- Is your auth logic actually sound?
- What happens in edge cases?
- Are there business logic vulnerabilities?
- What's your real attack surface?

**That's where humans come in.** [Book a security audit](https://shipwryte.com/audit) for a comprehensive review.

## License

MIT
