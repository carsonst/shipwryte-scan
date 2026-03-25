import { NextResponse } from "next/server";
import { randomUUID } from "crypto";
import { writeFile, mkdir, rm } from "fs/promises";
import { execFile } from "child_process";
import { promisify } from "util";
import { tmpdir } from "os";
import { join } from "path";

const exec = promisify(execFile);

async function runScan(codeDir: string, id: string) {
  const scanResult = await exec(
    "node",
    [join(process.cwd(), "..", "bin", "cli.js"), codeDir, "--json", "-q"],
    { timeout: 120000, maxBuffer: 10 * 1024 * 1024 }
  ).catch((e) => {
    // scanner exits non-zero on findings, but still outputs JSON
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

export async function POST(request: Request) {
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
        return new NextResponse("Missing repo URL", { status: 400 });
      }

      // Parse and strictly validate the GitHub URL
      const repoUrlStr = repoUrl.trim().replace(/\.git$/, "").replace(/\/+$/, "");
      let parsed: URL;
      try {
        parsed = new URL(
          repoUrlStr.startsWith("http") ? repoUrlStr : `https://${repoUrlStr}`
        );
      } catch {
        return new NextResponse("Invalid URL", { status: 400 });
      }

      if (parsed.hostname !== "github.com" && parsed.hostname !== "www.github.com") {
        return new NextResponse("Only public GitHub repos are supported", {
          status: 400,
        });
      }

      // Extract owner/repo from pathname, reject anything weird
      const parts = parsed.pathname.replace(/^\/+/, "").split("/");
      if (parts.length < 2 || !parts[0] || !parts[1]) {
        return new NextResponse("Invalid GitHub repo URL. Expected: github.com/owner/repo", {
          status: 400,
        });
      }
      const owner = parts[0].replace(/[^a-zA-Z0-9_.-]/g, "");
      const repo = parts[1].replace(/[^a-zA-Z0-9_.-]/g, "");
      const safeCloneUrl = `https://github.com/${owner}/${repo}.git`;

      const codeDir = join(workDir, "repo");

      // Shallow clone — fast, only latest commit
      await exec("git", ["clone", "--depth", "1", safeCloneUrl, codeDir], {
        timeout: 60000,
      }).catch(() => {
        throw new Error(
          "Could not clone repo. Make sure it exists and is public."
        );
      });

      const result = await runScan(codeDir, id);
      return NextResponse.json(result);
    }

    // Zip file upload
    const formData = await request.formData();
    const file = formData.get("file") as File | null;

    if (!file) {
      return new NextResponse("No file uploaded", { status: 400 });
    }

    if (!file.name.endsWith(".zip")) {
      return new NextResponse("Only .zip files accepted", { status: 400 });
    }

    if (file.size > 50 * 1024 * 1024) {
      return new NextResponse("File too large (50MB max)", { status: 400 });
    }

    const zipPath = join(workDir, "upload.zip");
    const bytes = await file.arrayBuffer();
    await writeFile(zipPath, Buffer.from(bytes));

    const codeDir = join(workDir, "code");
    await mkdir(codeDir, { recursive: true });
    await exec("unzip", ["-q", "-o", zipPath, "-d", codeDir]);

    const result = await runScan(codeDir, id);
    return NextResponse.json(result);
  } catch (e) {
    const message = e instanceof Error ? e.message : "Scan failed";
    console.error("Scan error:", message);
    return new NextResponse(message, { status: 500 });
  } finally {
    rm(workDir, { recursive: true, force: true }).catch(() => {});
  }
}
