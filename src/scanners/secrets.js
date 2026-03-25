import { execFile } from 'child_process';
import { promisify } from 'util';
import { readdirSync, readFileSync, statSync } from 'fs';
import path from 'path';

const execFileAsync = promisify(execFile);

// Patterns for secret detection (built-in fallback when trufflehog isn't installed)
const SECRET_PATTERNS = [
  { name: 'AWS Access Key', regex: /(?<![A-Za-z0-9/+=])AKIA[0-9A-Z]{16}(?![A-Za-z0-9/+=])/, severity: 'critical' },
  { name: 'AWS Secret Key', regex: /(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/, minContext: /aws_secret|secret_access_key|AWS_SECRET/i, severity: 'critical' },
  { name: 'GitHub Token', regex: /gh[pousr]_[A-Za-z0-9_]{36,255}/, severity: 'critical' },
  { name: 'GitHub Personal Access Token (Classic)', regex: /ghp_[A-Za-z0-9]{36}/, severity: 'critical' },
  { name: 'OpenAI API Key', regex: /sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}/, severity: 'critical' },
  { name: 'OpenAI API Key (Project)', regex: /sk-proj-[A-Za-z0-9_-]{40,200}/, severity: 'critical' },
  { name: 'Anthropic API Key', regex: /sk-ant-[A-Za-z0-9_-]{40,100}/, severity: 'critical' },
  { name: 'Stripe Secret Key', regex: /sk_live_[A-Za-z0-9]{24,99}/, severity: 'critical' },
  { name: 'Stripe Publishable Key', regex: /pk_live_[A-Za-z0-9]{24,99}/, severity: 'medium' },
  { name: 'Supabase Service Role Key', regex: /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]{50,500}\.[A-Za-z0-9_-]{20,100}/, minContext: /supabase|service_role|SUPABASE/i, severity: 'critical' },
  { name: 'Firebase API Key', regex: /AIza[0-9A-Za-z_-]{35}/, severity: 'high' },
  { name: 'Slack Token', regex: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}/, severity: 'critical' },
  { name: 'Twilio API Key', regex: /SK[a-f0-9]{32}/, severity: 'high' },
  { name: 'SendGrid API Key', regex: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/, severity: 'critical' },
  { name: 'Mailgun API Key', regex: /key-[0-9a-zA-Z]{32}/, severity: 'high' },
  { name: 'Private Key', regex: /-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/, severity: 'critical' },
  { name: 'Generic Secret Assignment', regex: /(password|secret|token|api_key|apikey|api_secret|access_token|auth_token|credentials)\s*[=:]\s*['"][A-Za-z0-9+/=_-]{8,}['"]/i, severity: 'high' },
  { name: 'Database Connection String', regex: /(mongodb(\+srv)?|postgres(ql)?|mysql|redis):\/\/[^\s'"]+:[^\s'"]+@[^\s'"]+/, severity: 'critical' },
  { name: 'Hardcoded JWT Secret', regex: /(jwt_secret|JWT_SECRET|jwtSecret)\s*[=:]\s*['"][^'"]{8,}['"]/, severity: 'critical' },
  // Tier 2: Additional secret patterns
  { name: 'GitHub Fine-Grained PAT', regex: /github_pat_[A-Za-z0-9_]{22,255}/, severity: 'critical' },
  { name: 'Google Cloud Service Account Key', regex: /"type"\s*:\s*"service_account"/, minContext: /"private_key"/i, severity: 'critical' },
  { name: 'Azure Connection String', regex: /DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{40,}/, severity: 'critical' },
  { name: 'Azure Storage SAS Token', regex: /[?&]sig=[A-Za-z0-9%+/=]{40,}/, minContext: /\.blob\.core\.windows\.net|\.queue\.core\.windows\.net|\.table\.core\.windows\.net/i, severity: 'critical' },
  { name: 'HuggingFace Token', regex: /hf_[A-Za-z0-9]{34,}/, severity: 'critical' },
  { name: 'Datadog API Key', regex: /(?:DD_API_KEY|datadog_api_key|DATADOG_API_KEY)\s*[=:]\s*['"]?[a-f0-9]{32}['"]?/i, severity: 'high' },
  { name: 'Slack App-Level Token', regex: /xapp-[0-9]+-[A-Za-z0-9]+-[0-9]+-[a-f0-9]+/, severity: 'critical' },
  { name: 'Slack Webhook URL', regex: /hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/, severity: 'high' },
  { name: 'Vercel Token', regex: /vercel_[A-Za-z0-9_-]{24,}/, severity: 'critical' },
  { name: 'Netlify Token', regex: /nfp_[A-Za-z0-9]{40,}/, severity: 'critical' },
  { name: 'Replicate API Token', regex: /r8_[A-Za-z0-9]{36,}/, severity: 'critical' },
  { name: 'Clerk Secret Key', regex: /sk_live_[A-Za-z0-9]{24,}/, minContext: /clerk/i, severity: 'critical' },
  { name: 'Discord Bot Token', regex: /[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9-_]{6}\.[A-Za-z0-9-_]{27,}/, severity: 'critical' },
  { name: 'Telegram Bot Token', regex: /[0-9]{8,10}:[A-Za-z0-9_-]{35}/, minContext: /telegram|bot_token|TELEGRAM/i, severity: 'high' },
  { name: 'HashiCorp Vault Token', regex: /hvs\.[A-Za-z0-9_-]{24,}/, severity: 'critical' },
  { name: 'Doppler Token', regex: /dp\.st\.[A-Za-z0-9_-]{40,}/, severity: 'critical' },
  { name: 'Linear API Key', regex: /lin_api_[A-Za-z0-9]{40,}/, severity: 'high' },
  { name: 'Planetscale Token', regex: /pscale_tkn_[A-Za-z0-9_-]{40,}/, severity: 'critical' },
  { name: 'Turso Database Token', regex: /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/, minContext: /turso|libsql|TURSO/i, severity: 'critical' },
];

const IGNORE_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', '.next', '__pycache__',
  'venv', '.venv', 'vendor', '.cache', 'coverage', '.nyc_output',
]);

const SCAN_EXTENSIONS = new Set([
  '.js', '.ts', '.jsx', '.tsx', '.py', '.go', '.rb', '.java',
  '.env', '.yaml', '.yml', '.json', '.toml', '.cfg', '.conf',
  '.properties', '.sh', '.bash', '.zsh', '.sql', '.tf', '.hcl',
]);

function walkFiles(dir, maxDepth = 10) {
  const results = [];
  if (maxDepth <= 0) return results;

  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return results;
  }

  for (const entry of entries) {
    if (entry.name.startsWith('.') && entry.name !== '.env' && entry.name !== '.env.local' && entry.name !== '.env.production') continue;
    if (IGNORE_DIRS.has(entry.name)) continue;

    const fullPath = path.join(dir, entry.name);

    if (entry.isDirectory()) {
      results.push(...walkFiles(fullPath, maxDepth - 1));
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name).toLowerCase();
      // Always scan .env files regardless of extension check
      if (SCAN_EXTENSIONS.has(ext) || entry.name.startsWith('.env')) {
        results.push(fullPath);
      }
    }
  }

  return results;
}

export async function runSecretScanner(targetPath) {
  // Try trufflehog first
  try {
    const findings = await runTrufflehog(targetPath);
    if (findings.length > 0) return findings;
  } catch {
    // Fall through to built-in scanner
  }

  // Built-in pattern matching
  return runBuiltInSecretScanner(targetPath);
}

async function runTrufflehog(targetPath) {
  const { stdout } = await execFileAsync('trufflehog', [
    'filesystem', targetPath,
    '--json',
    '--no-update',
  ], { timeout: 120000, maxBuffer: 10 * 1024 * 1024 });

  if (!stdout.trim()) return [];

  return stdout.trim().split('\n')
    .filter(line => line.trim())
    .map(line => {
      try {
        const result = JSON.parse(line);
        return {
          scanner: 'trufflehog',
          severity: 'critical',
          category: 'secret',
          title: `Exposed Secret: ${result.DetectorName || 'Unknown'}`,
          description: `Found a ${result.DetectorName || 'secret'} in your codebase. This should never be committed to version control.`,
          file: result.SourceMetadata?.Data?.Filesystem?.file || 'unknown',
          line: result.SourceMetadata?.Data?.Filesystem?.line || null,
          recommendation: 'Remove the secret from source code, rotate the credential immediately, and use environment variables or a secrets manager instead.',
          raw: result.Raw ? `${result.Raw.substring(0, 6)}...` : null,
        };
      } catch {
        return null;
      }
    })
    .filter(Boolean);
}

function runBuiltInSecretScanner(targetPath) {
  const findings = [];
  const files = walkFiles(targetPath);

  for (const filePath of files) {
    let content;
    try {
      const stat = statSync(filePath);
      if (stat.size > 1024 * 1024) continue; // Skip files > 1MB
      content = readFileSync(filePath, 'utf-8');
    } catch {
      continue;
    }

    const lines = content.split('\n');
    const relPath = path.relative(targetPath, filePath);

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Skip comments
      if (line.trim().startsWith('//') && !line.includes('=')) continue;
      if (line.trim().startsWith('#') && !line.includes('=')) continue;

      for (const pattern of SECRET_PATTERNS) {
        const match = line.match(pattern.regex);
        if (!match) continue;

        // If pattern requires context, check surrounding lines
        if (pattern.minContext) {
          const context = lines.slice(Math.max(0, i - 3), i + 4).join('\n');
          if (!pattern.minContext.test(context)) continue;
        }

        // Skip if it looks like a placeholder
        const matchedValue = match[0];
        if (/^(your_|example_|xxx|placeholder|changeme|TODO|FIXME)/i.test(matchedValue)) continue;
        if (/^['"]?(your|example|test|dummy|fake|placeholder)/i.test(line.split(/[=:]/)[1]?.trim() || '')) continue;

        findings.push({
          scanner: 'shipwryte-secrets',
          severity: pattern.severity,
          category: 'secret',
          title: `${pattern.name} detected`,
          description: `Found what appears to be a ${pattern.name.toLowerCase()} in \`${relPath}\` on line ${i + 1}. Hardcoded secrets in source code can be extracted by anyone with repository access.`,
          file: relPath,
          line: i + 1,
          recommendation: 'Remove this secret from source code immediately. Use environment variables or a secrets manager. If this was committed to git, rotate the credential now — it may already be exposed in git history.',
        });

        break; // One finding per line
      }
    }
  }

  return findings;
}
