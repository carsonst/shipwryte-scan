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

      // Normalize URL — accept various GitHub URL formats
      let cleanUrl = repoUrl.trim();
      if (!cleanUrl.startsWith("https://") && !cleanUrl.startsWith("http://")) {
        cleanUrl = `https://${cleanUrl}`;
      }
      // Strip trailing slashes, .git suffix
      cleanUrl = cleanUrl.replace(/\/+$/, "").replace(/\.git$/, "");

      if (!cleanUrl.includes("github.com/")) {
        return new NextResponse("Only public GitHub repos are supported", {
          status: 400,
        });
      }

      const codeDir = join(workDir, "repo");

      // Shallow clone — fast, only latest commit
      await exec("git", ["clone", "--depth", "1", `${cleanUrl}.git`, codeDir], {
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
