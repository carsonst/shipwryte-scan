import { execFile } from 'child_process';
import { promisify } from 'util';
import { readFileSync, existsSync } from 'fs';
import path from 'path';

const execFileAsync = promisify(execFile);

export async function runDependencyScanner(targetPath) {
  // Try Trivy first
  try {
    return await runTrivy(targetPath);
  } catch {
    // Fall through to built-in
  }

  // Try npm audit
  try {
    return await runNpmAudit(targetPath);
  } catch {
    // Fall through
  }

  // Built-in: check for outdated/known-bad patterns
  return runBuiltInDepScanner(targetPath);
}

async function runTrivy(targetPath) {
  const { stdout } = await execFileAsync('trivy', [
    'fs', targetPath,
    '--format', 'json',
    '--scanners', 'vuln',
    '--severity', 'UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL',
  ], { timeout: 120000, maxBuffer: 10 * 1024 * 1024 });

  const result = JSON.parse(stdout);
  const findings = [];

  for (const target of result.Results || []) {
    for (const vuln of target.Vulnerabilities || []) {
      findings.push({
        scanner: 'trivy',
        severity: mapTrivySeverity(vuln.Severity),
        category: 'dependency',
        title: `${vuln.VulnerabilityID}: ${vuln.PkgName} ${vuln.InstalledVersion}`,
        description: vuln.Title || vuln.Description || `Known vulnerability in ${vuln.PkgName}`,
        file: target.Target || 'unknown',
        line: null,
        recommendation: vuln.FixedVersion
          ? `Update ${vuln.PkgName} to version ${vuln.FixedVersion} or later.`
          : `No fix available yet. Consider finding an alternative to ${vuln.PkgName}.`,
        cve: vuln.VulnerabilityID,
        installedVersion: vuln.InstalledVersion,
        fixedVersion: vuln.FixedVersion,
      });
    }
  }

  return findings;
}

function mapTrivySeverity(s) {
  switch (s?.toUpperCase()) {
    case 'CRITICAL': return 'critical';
    case 'HIGH': return 'high';
    case 'MEDIUM': return 'medium';
    default: return 'low';
  }
}

async function runNpmAudit(targetPath) {
  const lockFile = path.join(targetPath, 'package-lock.json');
  if (!existsSync(lockFile)) throw new Error('No package-lock.json');

  const { stdout } = await execFileAsync('npm', [
    'audit', '--json',
  ], { cwd: targetPath, timeout: 60000, maxBuffer: 10 * 1024 * 1024 });

  const result = JSON.parse(stdout);
  const findings = [];

  for (const [name, advisory] of Object.entries(result.vulnerabilities || {})) {
    findings.push({
      scanner: 'npm-audit',
      severity: mapNpmSeverity(advisory.severity),
      category: 'dependency',
      title: `Vulnerable dependency: ${name}`,
      description: `${name} has a known ${advisory.severity} severity vulnerability.${advisory.via?.[0]?.title ? ' ' + advisory.via[0].title : ''}`,
      file: 'package.json',
      line: null,
      recommendation: advisory.fixAvailable
        ? `Run \`npm audit fix\` or update ${name} manually.`
        : `No automatic fix available. Review if ${name} is necessary or find an alternative.`,
    });
  }

  return findings;
}

function mapNpmSeverity(s) {
  switch (s) {
    case 'critical': return 'critical';
    case 'high': return 'high';
    case 'moderate': return 'medium';
    default: return 'low';
  }
}

function runBuiltInDepScanner(targetPath) {
  const findings = [];

  // Check package.json
  const pkgPath = path.join(targetPath, 'package.json');
  if (existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'));
      const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };

      // Check for known-insecure patterns
      for (const [name, version] of Object.entries(allDeps)) {
        // Wildcard or latest versions
        if (version === '*' || version === 'latest') {
          findings.push({
            scanner: 'shipwryte-deps',
            severity: 'medium',
            category: 'dependency',
            title: `Unpinned dependency: ${name}`,
            description: `\`${name}\` is set to "${version}" which could pull in any version, including ones with known vulnerabilities.`,
            file: 'package.json',
            line: null,
            recommendation: `Pin ${name} to a specific version range (e.g., "^1.2.3").`,
          });
        }

        // Git URLs (potentially risky)
        if (version.startsWith('git') || version.includes('github.com')) {
          findings.push({
            scanner: 'shipwryte-deps',
            severity: 'medium',
            category: 'dependency',
            title: `Git dependency: ${name}`,
            description: `\`${name}\` is installed from a git URL. This bypasses the npm registry and could be tampered with.`,
            file: 'package.json',
            line: null,
            recommendation: `If possible, use a published npm package instead of a git URL for ${name}.`,
          });
        }
      }

      // No lock file
      if (!existsSync(path.join(targetPath, 'package-lock.json')) && !existsSync(path.join(targetPath, 'yarn.lock')) && !existsSync(path.join(targetPath, 'pnpm-lock.yaml'))) {
        findings.push({
          scanner: 'shipwryte-deps',
          severity: 'medium',
          category: 'dependency',
          title: 'No lock file found',
          description: 'No package-lock.json, yarn.lock, or pnpm-lock.yaml found. Without a lock file, dependency versions can drift between installs.',
          file: 'package.json',
          line: null,
          recommendation: 'Run `npm install` or `yarn install` to generate a lock file and commit it to version control.',
        });
      }
    } catch {
      // Skip if package.json is malformed
    }
  }

  // Check requirements.txt (Python)
  const reqPath = path.join(targetPath, 'requirements.txt');
  if (existsSync(reqPath)) {
    try {
      const content = readFileSync(reqPath, 'utf-8');
      const lines = content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        if (!line || line.startsWith('#')) continue;
        // Unpinned dependency
        if (!line.includes('==') && !line.includes('>=') && !line.includes('~=')) {
          const pkgName = line.split(/[<>=!]/)[0].trim();
          if (pkgName) {
            findings.push({
              scanner: 'shipwryte-deps',
              severity: 'low',
              category: 'dependency',
              title: `Unpinned Python dependency: ${pkgName}`,
              description: `\`${pkgName}\` in requirements.txt has no version constraint.`,
              file: 'requirements.txt',
              line: i + 1,
              recommendation: `Pin ${pkgName} to a specific version (e.g., "${pkgName}==1.2.3").`,
            });
          }
        }
      }
    } catch {
      // Skip
    }
  }

  return findings;
}
