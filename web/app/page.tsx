"use client";

import { useState, useRef, useCallback } from "react";
import Image from "next/image";

type ScanState = "idle" | "uploading" | "scanning" | "done" | "error";

interface Finding {
  severity: string;
  type: string;
  title: string;
  description: string;
  file?: string;
  line?: number;
  recommendation?: string;
}

interface ScanResult {
  id: string;
  score: number;
  grade: string;
  findings: Finding[];
  scannedFiles: number;
  duration: number;
}

function Logo() {
  return (
    <a href="https://shipwryte.com" className="flex items-center gap-3 no-underline">
      <Image
        src="/logo-ship.png"
        alt="Shipwryte"
        width={120}
        height={40}
        className="h-8 w-auto"
      />
      <span className="text-[var(--fg-muted)] font-mono text-xs">/scan</span>
    </a>
  );
}

export default function Home() {
  const [state, setState] = useState<ScanState>("idle");
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string>("");
  const [dragOver, setDragOver] = useState(false);
  const [email, setEmail] = useState("");
  const [emailSubmitted, setEmailSubmitted] = useState(false);
  const [repoUrl, setRepoUrl] = useState("");
  const fileRef = useRef<HTMLInputElement>(null);

  const handleRepoScan = useCallback(async (url: string) => {
    const trimmed = url.trim();
    if (!trimmed.includes("github.com/")) {
      setError("Enter a public GitHub repo URL.");
      setState("error");
      return;
    }

    setState("scanning");
    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repoUrl: trimmed }),
      });
      if (!res.ok) {
        const msg = await res.text();
        throw new Error(msg || "Scan failed");
      }
      const data = await res.json();
      setResult(data);
      setState("done");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Something went wrong.");
      setState("error");
    }
  }, []);

  const handleUpload = useCallback(async (file: File) => {
    if (!file.name.endsWith(".zip")) {
      setError("Only .zip files are supported.");
      setState("error");
      return;
    }
    if (file.size > 50 * 1024 * 1024) {
      setError("File size limit is 50MB.");
      setState("error");
      return;
    }

    setState("uploading");
    const form = new FormData();
    form.append("file", file);

    try {
      setState("scanning");
      const res = await fetch("/api/scan", { method: "POST", body: form });
      if (!res.ok) {
        const msg = await res.text();
        throw new Error(msg || "Scan failed");
      }
      const data = await res.json();
      setResult(data);
      setState("done");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Something went wrong.");
      setState("error");
    }
  }, []);

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragOver(false);
      const file = e.dataTransfer.files[0];
      if (file) handleUpload(file);
    },
    [handleUpload]
  );

  const onFileChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (file) handleUpload(file);
    },
    [handleUpload]
  );

  const reset = () => {
    setState("idle");
    setResult(null);
    setError("");
    setEmailSubmitted(false);
    if (fileRef.current) fileRef.current.value = "";
  };

  const severityColor = (s: string) => {
    switch (s) {
      case "critical":
        return "text-[var(--destructive)]";
      case "high":
        return "text-[var(--warning)]";
      case "medium":
        return "text-yellow-400";
      default:
        return "text-[var(--fg-muted)]";
    }
  };

  const gradeColor = (g: string) => {
    if (g === "A") return "text-green-400";
    if (g === "B") return "text-green-300";
    if (g === "C") return "text-yellow-400";
    if (g === "D") return "text-[var(--warning)]";
    return "text-[var(--destructive)]";
  };

  return (
    <div className="flex flex-col min-h-screen">
      {/* nav */}
      <nav className="border-b border-[var(--border)] px-8 py-4 flex items-center justify-between">
        <Logo />
        <a
          href="https://github.com/carsonst/shipwryte-scan"
          target="_blank"
          rel="noopener"
          className="text-[var(--fg-muted)] font-mono text-xs uppercase tracking-wider hover:text-[var(--fg)] no-underline transition-colors"
        >
          GitHub
        </a>
      </nav>

      <main className="flex-1 flex flex-col items-center justify-center px-6 py-20 max-w-2xl mx-auto w-full">
        {state === "idle" && (
          <>
            <div className="mb-12 text-center">
              <h1 className="text-3xl font-semibold tracking-tight mb-3">
                Your AI app works.
                <br />
                <span
                  style={{
                    background: "linear-gradient(135deg, #6352F4, #ACA1ED)",
                    WebkitBackgroundClip: "text",
                    WebkitTextFillColor: "transparent",
                  }}
                >
                  Is it secure?
                </span>
              </h1>
              <p className="text-[var(--fg-muted)] text-sm max-w-md mx-auto leading-relaxed">
                Hardcoded API keys, vulnerable packages, injection flaws — the
                stuff AI tools don&apos;t check for. Paste your repo and find
                out in 60 seconds.
              </p>
            </div>

            {/* repo URL input */}
            <form
              onSubmit={(e) => {
                e.preventDefault();
                if (repoUrl.trim()) handleRepoScan(repoUrl);
              }}
              className="w-full flex gap-2"
            >
              <input
                type="text"
                value={repoUrl}
                onChange={(e) => setRepoUrl(e.target.value)}
                placeholder="https://github.com/you/your-project"
                className="flex-1 bg-[var(--surface)] border border-[var(--border)] px-4 py-3 text-sm text-[var(--fg)] outline-none focus:border-[var(--primary)] placeholder:text-[var(--fg-muted)] transition-colors font-mono"
              />
              <button
                type="submit"
                className="bg-[var(--primary)] hover:bg-[var(--primary-hover)] text-white px-6 py-3 text-sm font-medium cursor-pointer transition-colors shrink-0"
              >
                Scan
              </button>
            </form>
            <p className="text-[var(--fg-muted)] text-[10px] mt-2 w-full opacity-60">
              Public repos only. Nothing stored. Results deleted after 24 hours.
            </p>

            {/* or zip upload */}
            <div className="mt-6 w-full flex items-center gap-3">
              <div className="flex-1 border-t border-[var(--border)]" />
              <span className="text-[var(--fg-muted)] text-xs">or</span>
              <div className="flex-1 border-t border-[var(--border)]" />
            </div>
            <div
              onDragOver={(e) => {
                e.preventDefault();
                setDragOver(true);
              }}
              onDragLeave={() => setDragOver(false)}
              onDrop={onDrop}
              onClick={() => fileRef.current?.click()}
              className={`
                w-full border border-dashed cursor-pointer transition-all
                py-6 text-center mt-4
                ${
                  dragOver
                    ? "border-[var(--primary)] bg-[#6352F408]"
                    : "border-[var(--border)] hover:border-[var(--fg-muted)]"
                }
              `}
            >
              <p className="text-[var(--fg-muted)] text-xs">
                {dragOver ? "Drop it" : "Drop a .zip if your repo is private"} &middot; 50MB max
              </p>
            </div>
            <input
              ref={fileRef}
              type="file"
              accept=".zip"
              onChange={onFileChange}
              className="hidden"
            />

            {/* what we check */}
            <div className="mt-12 w-full grid grid-cols-3 gap-4 text-center">
              {[
                { label: "Secrets", desc: "API keys, tokens, credentials" },
                { label: "Dependencies", desc: "Known CVEs, unpinned versions" },
                { label: "Code", desc: "SQLi, XSS, command injection" },
              ].map((item) => (
                <div
                  key={item.label}
                  className="border border-[var(--border)] p-4"
                >
                  <p className="text-[var(--fg)] text-sm font-medium mb-1">
                    {item.label}
                  </p>
                  <p className="text-[var(--fg-muted)] text-xs">{item.desc}</p>
                </div>
              ))}
            </div>

            {/* CLI */}
            <div className="mt-10 w-full border-t border-[var(--border)] pt-6">
              <p className="text-[var(--fg-muted)] text-xs mb-3 font-mono uppercase tracking-wider">
                Prefer the terminal?
              </p>
              <div className="bg-[var(--surface)] border border-[var(--border)] px-4 py-3 font-mono text-sm">
                <span className="text-[var(--accent)]">$</span>{" "}
                <span className="text-[var(--fg)]">
                  npx @shipwryte/scan ./your-project
                </span>
              </div>
            </div>
          </>
        )}

        {(state === "uploading" || state === "scanning") && (
          <div className="text-center">
            <div className="mb-4">
              <div
                className="inline-block w-5 h-5 border-2 border-[var(--primary)] border-t-transparent rounded-full animate-spin"
              />
            </div>
            <p className="text-[var(--fg-muted)] text-sm">
              {state === "uploading"
                ? "Uploading..."
                : "Scanning for vulnerabilities..."}
            </p>
          </div>
        )}

        {state === "error" && (
          <div className="text-center">
            <p className="text-[var(--destructive)] text-sm mb-4">{error}</p>
            <button
              onClick={reset}
              className="text-sm text-[var(--fg-muted)] underline underline-offset-4 hover:text-[var(--fg)] cursor-pointer"
            >
              Try again
            </button>
          </div>
        )}

        {state === "done" && result && (
          <div className="w-full">
            {/* score header */}
            <div className="flex items-baseline justify-between mb-8 pb-6 border-b border-[var(--border)]">
              <div>
                <p className="text-[var(--fg-muted)] text-xs mb-1 font-mono uppercase tracking-wider">
                  Security Score
                </p>
                <span className="text-[var(--fg)] text-4xl font-bold">
                  {result.score}
                </span>
                <span className="text-[var(--fg-muted)] text-lg">/100</span>
              </div>
              <div className="text-right">
                <p className="text-[var(--fg-muted)] text-xs mb-1 font-mono uppercase tracking-wider">
                  Grade
                </p>
                <span
                  className={`text-4xl font-bold ${gradeColor(result.grade)}`}
                >
                  {result.grade}
                </span>
              </div>
            </div>

            {/* severity summary */}
            <div className="flex gap-6 mb-6 text-sm font-mono">
              {["critical", "high", "medium", "low"].map((sev) => {
                const count = result.findings.filter(
                  (f) => f.severity === sev
                ).length;
                if (count === 0) return null;
                return (
                  <span key={sev} className={severityColor(sev)}>
                    {count}{" "}
                    <span className="uppercase text-xs">{sev}</span>
                  </span>
                );
              })}
              <span className="text-[var(--fg-muted)] ml-auto text-xs">
                {result.scannedFiles} files &middot; {result.duration}s
              </span>
            </div>

            {/* findings list — first 3 visible */}
            <div className="space-y-0">
              {result.findings.slice(0, 3).map((f, i) => (
                <div
                  key={i}
                  className="border-b border-[var(--border)] py-4 flex gap-4 text-sm"
                >
                  <span
                    className={`${severityColor(f.severity)} font-mono uppercase text-xs w-16 shrink-0 pt-0.5`}
                  >
                    {f.severity}
                  </span>
                  <div className="min-w-0">
                    <p className="text-[var(--fg)]">{f.title}</p>
                    {f.file && (
                      <p className="text-[var(--fg-muted)] text-xs mt-1 truncate font-mono">
                        {f.file}
                        {f.line ? `:${f.line}` : ""}
                      </p>
                    )}
                  </div>
                </div>
              ))}
            </div>

            {/* email gate for remaining findings */}
            {result.findings.length > 3 && !emailSubmitted && (
              <div className="mt-6 border border-[var(--border)] bg-[var(--surface)] p-6">
                <p className="text-sm text-[var(--fg)] mb-1 font-medium">
                  {result.findings.length - 3} more findings in this scan.
                </p>
                <p className="text-xs text-[var(--fg-muted)] mb-4">
                  Enter your email to unlock the full report. We&apos;ll also
                  send a copy to your inbox.
                </p>
                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    if (email.includes("@")) {
                      setEmailSubmitted(true);
                      fetch("/api/lead", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({
                          email,
                          scanId: result.id,
                          score: result.score,
                          grade: result.grade,
                        }),
                      });
                    }
                  }}
                  className="flex gap-2"
                >
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="you@company.com"
                    className="flex-1 bg-[var(--bg)] border border-[var(--border)] px-3 py-2 text-sm text-[var(--fg)] outline-none focus:border-[var(--primary)] placeholder:text-[var(--fg-muted)] transition-colors"
                  />
                  <button
                    type="submit"
                    className="bg-[var(--primary)] hover:bg-[var(--primary-hover)] text-white px-5 py-2 text-sm font-medium cursor-pointer transition-colors"
                  >
                    Unlock Full Report
                  </button>
                </form>
              </div>
            )}

            {/* remaining findings after email */}
            {emailSubmitted && result.findings.length > 3 && (
              <div className="space-y-0 mt-0">
                {result.findings.slice(3).map((f, i) => (
                  <div
                    key={i + 3}
                    className="border-b border-[var(--border)] py-4 flex gap-4 text-sm"
                  >
                    <span
                      className={`${severityColor(f.severity)} font-mono uppercase text-xs w-16 shrink-0 pt-0.5`}
                    >
                      {f.severity}
                    </span>
                    <div className="min-w-0">
                      <p className="text-[var(--fg)]">{f.title}</p>
                      {f.file && (
                        <p className="text-[var(--fg-muted)] text-xs mt-1 truncate font-mono">
                          {f.file}
                          {f.line ? `:${f.line}` : ""}
                        </p>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* CTA */}
            <div className="mt-10 pt-6 border-t border-[var(--border)] flex items-center justify-between gap-4">
              <div>
                <p className="text-sm text-[var(--fg)] font-medium">
                  This is the surface scan.
                </p>
                <p className="text-xs text-[var(--fg-muted)] mt-1">
                  Our full audit covers auth, rate limiting, CORS, deployment,
                  and more.
                </p>
                <a
                  href="https://shipwryte.com"
                  className="inline-block mt-3 bg-[var(--primary)] hover:bg-[var(--primary-hover)] text-white px-5 py-2 text-sm font-medium no-underline transition-colors"
                >
                  Get a Full Audit
                </a>
              </div>
              <button
                onClick={reset}
                className="text-sm text-[var(--fg-muted)] border border-[var(--border)] px-4 py-2 hover:border-[var(--fg-muted)] cursor-pointer bg-transparent transition-colors shrink-0"
              >
                Scan Another
              </button>
            </div>
          </div>
        )}
      </main>

      {/* footer */}
      <footer className="border-t border-[var(--border)] px-8 py-4 flex justify-between items-center text-xs text-[var(--fg-muted)]">
        <a
          href="https://shipwryte.com"
          className="flex items-center gap-2 no-underline hover:opacity-80 transition-opacity"
        >
          <Image
            src="/logo-ship.png"
            alt="Shipwryte"
            width={20}
            height={20}
            className="w-5 h-5"
          />
          <span className="font-mono font-bold tracking-widest uppercase text-[10px] text-[var(--fg-muted)]">
            SHIPWRYTE
          </span>
        </a>
        <span>Your code stays between us.</span>
      </footer>
    </div>
  );
}
