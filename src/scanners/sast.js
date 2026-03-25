import { execFile } from 'child_process';
import { promisify } from 'util';
import { readdirSync, readFileSync, statSync, existsSync } from 'fs';
import path from 'path';

const execFileAsync = promisify(execFile);

export async function runSASTScanner(targetPath) {
  // Try Semgrep first
  try {
    const findings = await runSemgrep(targetPath);
    // Merge with built-in patterns
    const builtIn = runBuiltInSAST(targetPath);
    return dedup([...findings, ...builtIn]);
  } catch {
    // Fall through to built-in only
  }

  return runBuiltInSAST(targetPath);
}

async function runSemgrep(targetPath) {
  // Check for custom rules
  const rulesDir = path.join(path.dirname(new URL(import.meta.url).pathname), '..', 'rules');
  const rulesArgs = existsSync(rulesDir)
    ? ['--config', rulesDir]
    : [];

  const { stdout } = await execFileAsync('semgrep', [
    'scan',
    '--json',
    '--config', 'auto',
    ...rulesArgs,
    targetPath,
  ], { timeout: 180000, maxBuffer: 20 * 1024 * 1024 });

  const result = JSON.parse(stdout);
  const findings = [];

  for (const r of result.results || []) {
    findings.push({
      scanner: 'semgrep',
      severity: mapSemgrepSeverity(r.extra?.severity),
      category: 'code',
      title: r.check_id?.split('.').pop() || 'Code issue',
      description: r.extra?.message || `Security issue found in ${r.path}`,
      file: path.relative(targetPath, r.path),
      line: r.start?.line || null,
      recommendation: r.extra?.fix || 'Review and fix the flagged code.',
      ruleId: r.check_id,
    });
  }

  return findings;
}

function mapSemgrepSeverity(s) {
  switch (s?.toUpperCase()) {
    case 'ERROR': return 'high';
    case 'WARNING': return 'medium';
    case 'INFO': return 'low';
    default: return 'medium';
  }
}

// Built-in pattern-based SAST scanner
const SAST_RULES = [
  // SQL Injection
  {
    id: 'sql-injection',
    title: 'Potential SQL Injection',
    pattern: /(?:query|execute|exec|raw)\s*\(\s*[`'"].*\$\{|(?:query|execute|exec|raw)\s*\(\s*(?:['"].*['"])?\s*\+/i,
    fileTypes: ['.js', '.ts', '.jsx', '.tsx'],
    severity: 'critical',
    description: 'SQL query appears to use string concatenation or template literals with user input. This can lead to SQL injection attacks.',
    recommendation: 'Use parameterized queries or prepared statements instead of string concatenation.',
  },
  // NoSQL Injection
  {
    id: 'nosql-injection',
    title: 'Potential NoSQL Injection',
    pattern: /\.(find|findOne|update|delete|remove)\(\s*\{.*req\.(body|query|params)/,
    fileTypes: ['.js', '.ts'],
    severity: 'high',
    description: 'MongoDB query directly uses request parameters without validation, which can enable NoSQL injection.',
    recommendation: 'Validate and sanitize user input before using it in database queries. Use a schema validation library like Joi or Zod.',
  },
  // XSS via dangerouslySetInnerHTML
  {
    id: 'xss-dangerouslysetinnerhtml',
    title: 'Cross-Site Scripting (XSS) Risk',
    pattern: /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:/,
    fileTypes: ['.jsx', '.tsx', '.js', '.ts'],
    severity: 'high',
    description: 'Using `dangerouslySetInnerHTML` can lead to XSS attacks if the HTML content is not properly sanitized.',
    recommendation: 'Avoid dangerouslySetInnerHTML when possible. If necessary, use a sanitization library like DOMPurify.',
  },
  // eval() usage
  {
    id: 'eval-usage',
    title: 'Use of eval()',
    pattern: /\beval\s*\(/,
    fileTypes: ['.js', '.ts', '.jsx', '.tsx'],
    severity: 'high',
    description: 'eval() executes arbitrary code and is a major security risk, especially with user-controlled input.',
    recommendation: 'Remove eval() and use safer alternatives like JSON.parse() or Function constructors with strict input validation.',
  },
  // CORS wildcard
  {
    id: 'cors-wildcard',
    title: 'CORS Wildcard Configuration',
    pattern: /(?:Access-Control-Allow-Origin|origin)\s*[=:]\s*['"]\*['"]/i,
    fileTypes: ['.js', '.ts', '.jsx', '.tsx', '.py', '.go'],
    severity: 'medium',
    description: 'CORS is configured to allow requests from any origin (`*`). This can expose your API to cross-origin attacks.',
    recommendation: 'Restrict CORS to specific trusted domains instead of using a wildcard.',
  },
  // CORS with credentials and wildcard
  {
    id: 'cors-credentials-wildcard',
    title: 'CORS with Credentials and Wildcard',
    pattern: /credentials\s*:\s*true/,
    fileTypes: ['.js', '.ts'],
    severity: 'high',
    description: 'CORS is configured to send credentials. If combined with a wildcard origin, this is a serious security issue.',
    recommendation: 'Never use credentials: true with a wildcard origin. Specify exact allowed origins.',
  },
  // Hardcoded password in auth
  {
    id: 'hardcoded-password',
    title: 'Hardcoded Password',
    pattern: /(?:password|passwd|pwd)\s*[=:]\s*['"][^'"]{4,}['"]/i,
    fileTypes: ['.js', '.ts', '.jsx', '.tsx', '.py', '.go', '.java'],
    severity: 'high',
    description: 'A password appears to be hardcoded in source code.',
    recommendation: 'Use environment variables or a secrets manager for passwords.',
  },
  // Missing password hashing
  {
    id: 'no-password-hash',
    title: 'Password Stored Without Hashing',
    pattern: /(?:password|passwd)\s*[=:]\s*(?:req\.body|request\.|params\.).*(?:save|create|insert|update)/i,
    fileTypes: ['.js', '.ts'],
    severity: 'critical',
    description: 'Password appears to be stored directly from user input without hashing.',
    recommendation: 'Always hash passwords using bcrypt, argon2, or scrypt before storing them.',
  },
  // Weak JWT secret
  {
    id: 'weak-jwt-secret',
    title: 'Weak JWT Configuration',
    pattern: /jwt\.sign\s*\([^)]*['"][^'"]{1,15}['"]/,
    fileTypes: ['.js', '.ts'],
    severity: 'high',
    description: 'JWT is being signed with what appears to be a short or weak secret.',
    recommendation: 'Use a strong, randomly generated secret (at least 256 bits) stored in environment variables.',
  },
  // No helmet/security headers
  {
    id: 'missing-security-headers',
    title: 'Missing Security Headers',
    pattern: /(?:express|app)\s*\(\s*\)/,
    antiPattern: /helmet/,
    fileTypes: ['.js', '.ts'],
    severity: 'medium',
    description: 'Express app initialized without helmet middleware. Security headers help prevent common attacks.',
    recommendation: 'Install and use the `helmet` package: `app.use(helmet())`',
    fileScope: true,
  },
  // Exposed debug/admin routes
  {
    id: 'exposed-debug-route',
    title: 'Exposed Debug/Admin Route',
    pattern: /\.(get|post|all|use)\s*\(\s*['"]\/(debug|admin|test|internal|_internal|_debug)/i,
    fileTypes: ['.js', '.ts'],
    severity: 'high',
    description: 'Debug or admin route found without apparent authentication middleware.',
    recommendation: 'Add authentication middleware to admin/debug routes, or remove them in production.',
  },
  // Open redirect
  {
    id: 'open-redirect',
    title: 'Potential Open Redirect',
    pattern: /(?:redirect|location)\s*[=(]\s*(?:req\.(?:query|body|params)\.|request\.)/i,
    fileTypes: ['.js', '.ts', '.py'],
    severity: 'medium',
    description: 'Redirect URL is taken directly from user input, which can enable open redirect attacks.',
    recommendation: 'Validate redirect URLs against a whitelist of allowed domains.',
  },
  // File upload without validation
  {
    id: 'unvalidated-upload',
    title: 'File Upload Without Validation',
    pattern: /multer|formidable|busboy|upload/i,
    antiPattern: /(?:fileFilter|mimetype|fileType|allowedTypes|accept)/i,
    fileTypes: ['.js', '.ts'],
    severity: 'high',
    description: 'File upload appears to lack file type validation, which can lead to remote code execution.',
    recommendation: 'Validate file types, limit file sizes, and store uploads outside the web root.',
    fileScope: true,
  },
  // Insecure cookie
  {
    id: 'insecure-cookie',
    title: 'Insecure Cookie Configuration',
    pattern: /cookie\s*[({]|setCookie|set-cookie/i,
    antiPattern: /(?:httpOnly|secure|sameSite)\s*:\s*true/i,
    fileTypes: ['.js', '.ts'],
    severity: 'medium',
    description: 'Cookies may be configured without httpOnly, secure, or sameSite flags.',
    recommendation: 'Set httpOnly: true, secure: true, and sameSite: "strict" on all cookies.',
    fileScope: true,
  },
  // exec/spawn with user input
  {
    id: 'command-injection',
    title: 'Potential Command Injection',
    pattern: /(?:exec|spawn|execSync|execFile)\s*\([^)]*(?:req\.|request\.|params\.|query\.|body\.|\$\{)/,
    fileTypes: ['.js', '.ts'],
    severity: 'critical',
    description: 'Shell command appears to include user-controlled input, enabling command injection.',
    recommendation: 'Never pass user input directly to shell commands. Use parameterized alternatives.',
  },
  // Disabled SSL verification
  {
    id: 'ssl-verification-disabled',
    title: 'SSL/TLS Verification Disabled',
    pattern: /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0|verify\s*=\s*False/i,
    fileTypes: ['.js', '.ts', '.py'],
    severity: 'high',
    description: 'SSL/TLS certificate verification is disabled, making connections vulnerable to man-in-the-middle attacks.',
    recommendation: 'Enable SSL certificate verification. If using self-signed certs in dev, use proper CA configuration.',
  },
  // Sensitive data in URL params
  {
    id: 'sensitive-url-params',
    title: 'Sensitive Data in URL Parameters',
    pattern: /[?&](password|token|secret|api_key|apikey|access_token|auth)=/i,
    fileTypes: ['.js', '.ts', '.jsx', '.tsx', '.py'],
    severity: 'medium',
    description: 'Sensitive data appears to be passed in URL parameters, which can be logged by servers and proxies.',
    recommendation: 'Send sensitive data in request headers or POST body instead of URL parameters.',
  },
  // Rate limiting missing
  {
    id: 'no-rate-limiting',
    title: 'No Rate Limiting Detected',
    pattern: /(?:app|router)\.(post|put|patch)\s*\(\s*['"]\/(?:login|auth|signin|signup|register|api)/i,
    antiPattern: /rate.?limit|throttle|express-rate-limit|express-slow-down/i,
    fileTypes: ['.js', '.ts'],
    severity: 'medium',
    description: 'Authentication or API endpoint found without rate limiting, which can enable brute-force attacks.',
    recommendation: 'Add rate limiting using express-rate-limit or similar middleware.',
    fileScope: true,
  },
  // Python specific: os.system
  {
    id: 'python-os-system',
    title: 'Use of os.system() in Python',
    pattern: /os\.system\s*\(/,
    fileTypes: ['.py'],
    severity: 'high',
    description: 'os.system() executes shell commands and is vulnerable to command injection.',
    recommendation: 'Use subprocess.run() with a list of arguments instead of os.system().',
  },
  // Python specific: pickle
  {
    id: 'python-pickle',
    title: 'Use of pickle with Untrusted Data',
    pattern: /pickle\.loads?\s*\(/,
    fileTypes: ['.py'],
    severity: 'high',
    description: 'pickle can execute arbitrary code during deserialization. Never use it with untrusted data.',
    recommendation: 'Use JSON or another safe serialization format for untrusted data.',
  },
  // .env in gitignore check
  {
    id: 'env-not-gitignored',
    title: '.env File May Not Be Gitignored',
    pattern: /^(?!.*\.env).*$/,
    checkFile: '.gitignore',
    severity: 'high',
    description: 'The .gitignore file does not appear to include .env files. Environment files often contain secrets.',
    recommendation: 'Add `.env*` to your .gitignore file to prevent committing secrets.',
  },
];

const IGNORE_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', '.next', '__pycache__',
  'venv', '.venv', 'vendor', '.cache', 'coverage', '.nyc_output',
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
    if (entry.name.startsWith('.') && entry.name !== '.gitignore') continue;
    if (IGNORE_DIRS.has(entry.name)) continue;

    const fullPath = path.join(dir, entry.name);

    if (entry.isDirectory()) {
      results.push(...walkFiles(fullPath, maxDepth - 1));
    } else if (entry.isFile()) {
      results.push(fullPath);
    }
  }

  return results;
}

function runBuiltInSAST(targetPath) {
  const findings = [];
  const files = walkFiles(targetPath);

  // Special checks
  checkGitignore(targetPath, findings);

  for (const filePath of files) {
    const ext = path.extname(filePath).toLowerCase();
    const relPath = path.relative(targetPath, filePath);

    let content;
    try {
      const stat = statSync(filePath);
      if (stat.size > 1024 * 1024) continue;
      content = readFileSync(filePath, 'utf-8');
    } catch {
      continue;
    }

    const lines = content.split('\n');

    for (const rule of SAST_RULES) {
      if (rule.checkFile) continue; // These are handled separately
      if (!rule.fileTypes.includes(ext)) continue;

      if (rule.fileScope) {
        // Check entire file content
        if (rule.pattern.test(content) && (!rule.antiPattern || !rule.antiPattern.test(content))) {
          findings.push({
            scanner: 'shipwryte-sast',
            severity: rule.severity,
            category: 'code',
            title: rule.title,
            description: rule.description.replace(/in source code/, `in \`${relPath}\``),
            file: relPath,
            line: null,
            recommendation: rule.recommendation,
            ruleId: rule.id,
          });
        }
      } else {
        // Check line by line
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          if (rule.pattern.test(line)) {
            findings.push({
              scanner: 'shipwryte-sast',
              severity: rule.severity,
              category: 'code',
              title: rule.title,
              description: `${rule.description} Found in \`${relPath}\` on line ${i + 1}.`,
              file: relPath,
              line: i + 1,
              recommendation: rule.recommendation,
              ruleId: rule.id,
            });
            break; // One finding per rule per file for line-level checks
          }
        }
      }
    }
  }

  return findings;
}

function checkGitignore(targetPath, findings) {
  const gitignorePath = path.join(targetPath, '.gitignore');
  const envPath = path.join(targetPath, '.env');

  if (existsSync(envPath)) {
    if (!existsSync(gitignorePath)) {
      findings.push({
        scanner: 'shipwryte-sast',
        severity: 'high',
        category: 'config',
        title: '.env file exists but no .gitignore found',
        description: 'A .env file exists but there is no .gitignore file. The .env file (which likely contains secrets) may be committed to version control.',
        file: '.env',
        line: null,
        recommendation: 'Create a .gitignore file and add `.env*` to it.',
        ruleId: 'env-not-gitignored',
      });
    } else {
      const content = readFileSync(gitignorePath, 'utf-8');
      if (!content.includes('.env')) {
        findings.push({
          scanner: 'shipwryte-sast',
          severity: 'high',
          category: 'config',
          title: '.env file not in .gitignore',
          description: '.env file exists but is not listed in .gitignore. Secrets in .env may be exposed in version control.',
          file: '.gitignore',
          line: null,
          recommendation: 'Add `.env*` to your .gitignore file.',
          ruleId: 'env-not-gitignored',
        });
      }
    }
  }
}

function dedup(findings) {
  const seen = new Set();
  return findings.filter(f => {
    const key = `${f.file}:${f.line}:${f.ruleId || f.title}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
