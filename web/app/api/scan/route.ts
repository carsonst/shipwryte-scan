import { NextResponse } from "next/server";
import { randomUUID } from "crypto";
import { writeFile, mkdir, rm } from "fs/promises";
import { execFile } from "child_process";
import { promisify } from "util";
import { tmpdir } from "os";
import { join } from "path";
import { createGunzip } from "zlib";
import { Readable } from "stream";
import { extract } from "tar";

const exec = promisify(execFile);

const ALLOWED_ORIGINS = [
  "https://shipwryte.com",
  "https://www.shipwryte.com",
  "http://localhost:3000",
  "http://localhost:5173",
];

function getCorsHeaders(request: Request) {
  const origin = request.headers.get("origin") || "";
  const allowed = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return {
    "Access-Control-Allow-Origin": allowed,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
}

export async function OPTIONS(request: Request) {
  return new NextResponse(null, { status: 204, headers: getCorsHeaders(request) });
}

function getScannerPath() {
  return join(
    process.cwd(),
    "node_modules",
    "@shipwryte",
    "scan",
    "bin",
    "cli.js"
  );
}

async function runScan(codeDir: string, id: string) {
  const scanResult = await exec(
    "node",
    [getScannerPath(), codeDir, "--json", "-q"],
    { timeout: 120000, maxBuffer: 10 * 1024 * 1024 }
  ).catch((e) => {
    if (e.stdout) return { stdout: e.stdout, stderr: e.stderr };
    throw e;
  });

  let parsed;
  try {
    parsed = JSON.parse(scanResult.stdout);
  } catch {
    throw new Error("Scan produced invalid output");
  }

  return {
    id,
    score: parsed.score ?? 0,
    grade: parsed.grade ?? "F",
    findings: parsed.findings ?? [],
    scannedFiles: parsed.scannedFiles ?? 0,
    duration: parsed.duration ?? 0,
  };
}

async function downloadAndExtractRepo(
  owner: string,
  repo: string,
  destDir: string
) {
  const tarballUrl = `https://api.github.com/repos/${owner}/${repo}/tarball`;
  const res = await fetch(tarballUrl, {
    headers: { "User-Agent": "shipwryte-scan" },
    redirect: "follow",
  });

  if (!res.ok) {
    if (res.status === 404) {
      throw new Error("Repo not found. Make sure it exists and is public.");
    }
    throw new Error(`GitHub API error: ${res.status}`);
  }

  const arrayBuf = await res.arrayBuffer();
  const tarPath = join(destDir, "repo.tar.gz");
  await writeFile(tarPath, Buffer.from(arrayBuf));

  // Extract using Node.js tar package — no shell commands needed
  const codeDir = join(destDir, "code");
  await mkdir(codeDir, { recursive: true });
  await extract({
    file: tarPath,
    cwd: codeDir,
    strip: 1,
  });

  return codeDir;
}

export async function POST(request: Request) {
  const cors = getCorsHeaders(request);
  const contentType = request.headers.get("content-type") || "";
  const id = randomUUID();
  const workDir = join(tmpdir(), `shipwryte-${id}`);

  try {
    await mkdir(workDir, { recursive: true });

    // GitHub repo URL
    if (contentType.includes("application/json")) {
      const body = await request.json();
      const { repoUrl } = body;

      if (!repoUrl || typeof repoUrl !== "string") {
        return new NextResponse("Missing repo URL", { status: 400, headers: cors });
      }

      const repoUrlStr = repoUrl
        .trim()
        .replace(/\.git$/, "")
        .replace(/\/+$/, "");
      let parsed: URL;
      try {
        parsed = new URL(
          repoUrlStr.startsWith("http") ? repoUrlStr : `https://${repoUrlStr}`
        );
      } catch {
        return new NextResponse("Invalid URL", { status: 400, headers: cors });
      }

      if (
        parsed.hostname !== "github.com" &&
        parsed.hostname !== "www.github.com"
      ) {
        return new NextResponse("Only public GitHub repos are supported", {
          status: 400, headers: cors,
        });
      }

      const parts = parsed.pathname.replace(/^\/+/, "").split("/");
      if (parts.length < 2 || !parts[0] || !parts[1]) {
        return new NextResponse(
          "Invalid GitHub repo URL. Expected: github.com/owner/repo",
          { status: 400, headers: cors }
        );
      }
      const owner = parts[0].replace(/[^a-zA-Z0-9_.-]/g, "");
      const repo = parts[1].replace(/[^a-zA-Z0-9_.-]/g, "");

      const codeDir = await downloadAndExtractRepo(owner, repo, workDir);
      const result = await runScan(codeDir, id);
      return NextResponse.json(result, { headers: cors });
    }

    // Zip file upload
    const formData = await request.formData();
    const file = formData.get("file") as File | null;

    if (!file) {
      return new NextResponse("No file uploaded", { status: 400, headers: cors });
    }

    if (!file.name.endsWith(".zip")) {
      return new NextResponse("Only .zip files accepted", { status: 400, headers: cors });
    }

    if (file.size > 50 * 1024 * 1024) {
      return new NextResponse("File too large (50MB max)", { status: 400, headers: cors });
    }

    const zipPath = join(workDir, "upload.zip");
    const bytes = await file.arrayBuffer();
    await writeFile(zipPath, Buffer.from(bytes));

    const codeDir = join(workDir, "code");
    await mkdir(codeDir, { recursive: true });

    // Try unzip CLI, fall back to Node.js unzipper
    try {
      await exec("unzip", ["-q", "-o", zipPath, "-d", codeDir]);
    } catch {
      // If unzip isn't available, use Node.js
      const { default: AdmZip } = await import("adm-zip");
      const zip = new AdmZip(zipPath);
      zip.extractAllTo(codeDir, true);
    }

    const result = await runScan(codeDir, id);
    return NextResponse.json(result, { headers: cors });
  } catch (e) {
    const message = e instanceof Error ? e.message : "Scan failed";
    console.error("Scan error:", message);
    return new NextResponse(message, { status: 500, headers: cors });
  } finally {
    rm(workDir, { recursive: true, force: true }).catch(() => {});
  }
}
