# Shipwryte Scan — Web UI

Web interface for the [@shipwryte/scan](https://www.npmjs.com/package/@shipwryte/scan) security scanner.

## Stack

- **Framework:** Next.js (App Router, TypeScript)
- **Styling:** Tailwind CSS v4 with CSS custom properties
- **No component library** — everything is hand-built

## Running locally

```bash
cd web
npm install
npm run dev
```

The dev server starts on `http://localhost:3000`. The scan API route shells out to `../bin/cli.js` (the parent scanner package), so make sure the parent project's dependencies are installed too.

## Project structure

```
web/
├── app/
│   ├── globals.css        # CSS variables, font config, base styles
│   ├── layout.tsx         # Root layout, metadata, OG tags
│   ├── page.tsx           # Main page: upload zone, results display, email gate
│   └── api/
│       ├── scan/route.ts  # POST: accepts .zip upload, unzips, runs scanner, returns JSON
│       └── lead/route.ts  # POST: captures email + scan metadata to leads.csv
├── public/                # Static assets (favicon, etc.)
└── README.md              # This file
```

## Brand guidelines

All UI should match the Shipwryte brand. Key rules:

- **Colors:** Dark background `#0A0A0A`, primary purple `#6352F4`, accent lavender `#ACA1ED`, muted text `#8C8C8C`, borders `#262626`
- **Gradient:** `linear-gradient(135deg, #6352F4, #ACA1ED)` used on the SHIPWRYTE wordmark and headline accents
- **Corners:** Sharp (0px border-radius). No rounded cards, buttons, or inputs.
- **Fonts:** Inter for body text, monospace (SF Mono / Fira Code / JetBrains Mono) for nav, labels, code, and the wordmark
- **Logo:** Text-based wordmark "SHIPWRYTE" in uppercase, tracking-widest, bold, with the purple gradient. Not an image file.
- **Tone:** Direct and confident. Speaks to founders who built fast with AI tools and need to know if their code is safe. No fluff, no buzzwords.
- **Layout:** Centered, narrow max-width (2xl / 672px). Dense but not cramped. Generous vertical spacing between sections.

## API routes

### POST /api/scan

Accepts `multipart/form-data` with a single `.zip` file. Extracts to a temp directory, runs the scanner with `--json -q` flags, returns structured JSON:

```json
{
  "id": "uuid",
  "score": 42,
  "grade": "F",
  "findings": [
    {
      "severity": "critical",
      "type": "hardcoded-secret",
      "message": "AWS access key found",
      "file": "src/config.js",
      "line": 12
    }
  ],
  "scannedFiles": 47,
  "duration": 1.2
}
```

Constraints: 50MB max file size, 60 second scan timeout. Temp files are cleaned up immediately after the scan.

### POST /api/lead

Accepts JSON with `email`, `scanId`, `score`, `grade`. Appends to `leads.csv`. This is a placeholder — replace with a real CRM/database integration before production use.

## Deployment notes

- The scan API runs shell commands (`unzip`, `node`) so it needs a server environment, not static/edge.
- `leads.csv` is a local file — won't persist on serverless platforms. Wire up a database before deploying to Vercel/Railway/etc.
- The scanner binary path is relative (`../bin/cli.js`) — in production, install `@shipwryte/scan` as a dependency and resolve the path from `node_modules`.

## What to change when updating

- **Copy/messaging:** Edit `page.tsx` — all text is inline, no CMS
- **Colors/fonts:** Edit `globals.css` CSS variables
- **Scanner behavior:** Edit `api/scan/route.ts` — that's where the CLI gets invoked
- **Lead capture:** Edit `api/lead/route.ts` — swap CSV for your CRM
- **Metadata/SEO:** Edit `layout.tsx` — title, description, OG tags
