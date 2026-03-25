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

  // ========== TIER 1: HIGH IMPACT ADDITIONS ==========

  // Path Traversal (CWE-22)
  {
    id: 'path-traversal',
    title: 'Potential Path Traversal',
    pattern: /(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|unlink|unlinkSync|access|accessSync|stat|statSync|open|openSync)\s*\([^)]*(?:req\.|request\.|params\.|query\.|body\.|\$\{)/,
    fileTypes: ['.js', '.ts'],
    severity: 'critical',
    description: 'File system operation uses user-controlled input, which can allow attackers to read or write arbitrary files via path traversal (../).',
    recommendation: 'Validate and sanitize file paths. Use path.resolve() and verify the resolved path is within an allowed directory.',
  },
  {
    id: 'path-traversal-express',
    title: 'Potential Path Traversal via sendFile/download',
    pattern: /(?:sendFile|download|sendfile)\s*\([^)]*(?:req\.|request\.|params\.|query\.|body\.|\$\{)/,
    fileTypes: ['.js', '.ts'],
    severity: 'critical',
    description: 'File serving operation uses user-controlled input. Attackers can traverse directories to access sensitive files.',
    recommendation: 'Use a static file middleware with a root directory constraint. Validate paths before serving files.',
  },

  // SSRF - Server-Side Request Forgery (CWE-918)
  {
    id: 'ssrf-fetch',
    title: 'Potential Server-Side Request Forgery (SSRF)',
    pattern: /(?:fetch|axios\.get|axios\.post|axios\(|http\.get|https\.get|request\(|got\(|ky\(|needle\()\s*\([^)]*(?:req\.|request\.|params\.|query\.|body\.|\$\{)/,
    fileTypes: ['.js', '.ts', '.jsx', '.tsx'],
    severity: 'critical',
    description: 'HTTP request is made with a user-controlled URL. Attackers can use this to access internal services, cloud metadata endpoints, or other restricted resources.',
    recommendation: 'Validate URLs against an allowlist. Block requests to private/internal IP ranges (10.x, 172.16-31.x, 192.168.x, 169.254.169.254). Use a URL parser to verify the hostname before making the request.',
  },

  // Weak Cryptography (CWE-327)
  {
    id: 'weak-crypto-md5',
    title: 'Weak Hash Algorithm: MD5',
    pattern: /(?:createHash|hashlib\.md5|MD5|md5)\s*\(\s*['"]?md5['"]?\s*\)|(?:crypto\.createHash)\s*\(\s*['"]md5['"]\)/i,
    fileTypes: ['.js', '.ts', '.py', '.go', '.java'],
    severity: 'high',
    description: 'MD5 is cryptographically broken and should not be used for security purposes (passwords, integrity checks, signatures).',
    recommendation: 'Use SHA-256 or SHA-3 for hashing. Use bcrypt, argon2, or scrypt for passwords.',
  },
  {
    id: 'weak-crypto-sha1',
    title: 'Weak Hash Algorithm: SHA-1',
    pattern: /(?:crypto\.createHash)\s*\(\s*['"]sha1?['"]\)|hashlib\.sha1/i,
    fileTypes: ['.js', '.ts', '.py', '.go', '.java'],
    severity: 'high',
    description: 'SHA-1 is deprecated and vulnerable to collision attacks. It should not be used for security purposes.',
    recommendation: 'Use SHA-256 or SHA-3 instead of SHA-1.',
  },
  {
    id: 'weak-crypto-des',
    title: 'Weak Encryption: DES/RC4',
    pattern: /(?:createCipher(?:iv)?)\s*\(\s*['"](?:des|des-ede|des-ede3|rc4|rc2)['"]/i,
    fileTypes: ['.js', '.ts', '.py'],
    severity: 'high',
    description: 'DES and RC4 are broken encryption algorithms with known vulnerabilities.',
    recommendation: 'Use AES-256-GCM or ChaCha20-Poly1305 for encryption.',
  },

  // Math.random() for security (CWE-338)
  {
    id: 'insecure-random',
    title: 'Insecure Random Number Generator',
    pattern: /Math\.random\s*\(\s*\)/,
    fileTypes: ['.js', '.ts', '.jsx', '.tsx'],
    severity: 'high',
    description: 'Math.random() is not cryptographically secure. Using it for tokens, session IDs, passwords, or any security-sensitive value is dangerous.',
    recommendation: 'Use crypto.randomUUID(), crypto.randomBytes(), or crypto.getRandomValues() for security-sensitive random values.',
  },

  // Prototype Pollution (CWE-1321)
  {
    id: 'prototype-pollution',
    title: 'Potential Prototype Pollution',
    pattern: /(?:Object\.assign|_\.merge|_\.extend|_\.defaultsDeep|lodash\.merge|deepmerge)\s*\([^)]*(?:req\.|request\.|params\.|query\.|body\.)/,
    fileTypes: ['.js', '.ts'],
    severity: 'high',
    description: 'Deep object merge with user-controlled input can lead to prototype pollution, allowing attackers to inject properties into all JavaScript objects.',
    recommendation: 'Validate and sanitize user input before merging. Use a schema validation library (Zod, Joi). Block __proto__, constructor, and prototype keys.',
  },
  {
    id: 'prototype-pollution-bracket',
    title: 'Potential Prototype Pollution via Bracket Notation',
    pattern: /\[(?:req\.|request\.|params\.|query\.|body\.)[^\]]+\]\s*=/,
    fileTypes: ['.js', '.ts'],
    severity: 'high',
    description: 'Dynamic property assignment with user-controlled keys can lead to prototype pollution if __proto__ or constructor is used as a key.',
    recommendation: 'Validate property names against a whitelist. Never use user input directly as object keys.',
  },

  // Loose Equality with User Input
  {
    id: 'loose-equality',
    title: 'Loose Equality Comparison (==) with User Input',
    pattern: /(?:req\.|request\.|params\.|query\.|body\.)[^\s]+\s*==[^=]|[^=!]==[^=]\s*(?:req\.|request\.|params\.|query\.|body\.)/,
    fileTypes: ['.js', '.ts'],
    severity: 'medium',
    description: 'Loose equality (==) with user input can lead to type coercion bypasses. For example, "0" == false is true.',
    recommendation: 'Always use strict equality (===) when comparing user input.',
  },

  // innerHTML XSS (beyond React)
  {
    id: 'xss-innerhtml',
    title: 'Cross-Site Scripting (XSS) via innerHTML',
    pattern: /\.innerHTML\s*=\s*(?!['"]<(?:br|hr|p|div)\s*\/?>['"])/,
    fileTypes: ['.js', '.ts', '.jsx', '.tsx'],
    severity: 'high',
    description: 'Setting innerHTML can execute arbitrary JavaScript if the content contains unsanitized user input.',
    recommendation: 'Use textContent instead of innerHTML. If HTML is needed, use a sanitization library like DOMPurify.',
  },
  {
    id: 'xss-document-write',
    title: 'Cross-Site Scripting (XSS) via document.write',
    pattern: /document\.write\s*\(/,
    fileTypes: ['.js', '.ts', '.jsx', '.tsx'],
    severity: 'high',
    description: 'document.write() can inject unsanitized content into the DOM, leading to XSS attacks.',
    recommendation: 'Use DOM manipulation methods (createElement, appendChild) instead of document.write().',
  },

  // YAML.load without safe_load (CWE-502)
  {
    id: 'yaml-unsafe-load',
    title: 'Unsafe YAML Deserialization',
    pattern: /yaml\.load\s*\(/,
    antiPattern: /safe_load|SafeLoader|yaml\.safe_load/,
    fileTypes: ['.py'],
    severity: 'high',
    description: 'yaml.load() can execute arbitrary Python code during deserialization. This is a remote code execution risk.',
    recommendation: 'Use yaml.safe_load() or yaml.load(data, Loader=SafeLoader) instead.',
    fileScope: true,
  },
  {
    id: 'js-yaml-unsafe',
    title: 'Unsafe YAML Parsing',
    pattern: /yaml\.load\s*\([^)]*\{[^}]*schema\s*:\s*yaml\.DEFAULT_SCHEMA/,
    fileTypes: ['.js', '.ts'],
    severity: 'high',
    description: 'YAML parsing with DEFAULT_SCHEMA can instantiate JavaScript objects, leading to code execution.',
    recommendation: 'Use yaml.load() with the default safe schema, or use JSON instead.',
  },

  // Sensitive Data in Logs (CWE-532)
  {
    id: 'sensitive-data-logged',
    title: 'Sensitive Data May Be Logged',
    pattern: /(?:console\.log|console\.info|console\.debug|logger?\.\w+)\s*\([^)]*(?:password|secret|token|apiKey|api_key|authorization|credential|private_key|access_token)/i,
    fileTypes: ['.js', '.ts', '.jsx', '.tsx', '.py'],
    severity: 'high',
    description: 'Sensitive data (passwords, tokens, keys) appears to be logged. Logs are often stored in plaintext and accessible to many people.',
    recommendation: 'Never log sensitive data. If debugging auth, log the event type and user ID only, not the credential.',
  },

  // Missing CSRF Protection
  {
    id: 'no-csrf-protection',
    title: 'No CSRF Protection Detected',
    pattern: /(?:app|router)\.(post|put|patch|delete)\s*\(/,
    antiPattern: /csrf|csurf|csrfToken|_csrf|xsrf|XSRF/i,
    fileTypes: ['.js', '.ts'],
    severity: 'medium',
    description: 'State-changing endpoints detected without CSRF protection. Attackers can trick users into making unintended requests.',
    recommendation: 'Implement CSRF tokens or use SameSite cookies. For APIs, validate the Origin/Referer header.',
    fileScope: true,
  },

  // JWT Algorithm None Attack
  {
    id: 'jwt-none-algorithm',
    title: 'JWT "none" Algorithm Allowed',
    pattern: /algorithms?\s*:\s*\[.*['"]none['"]/i,
    fileTypes: ['.js', '.ts'],
    severity: 'critical',
    description: 'JWT verification allows the "none" algorithm, which means tokens can be forged without a secret key.',
    recommendation: 'Explicitly specify allowed algorithms: algorithms: ["HS256"] or ["RS256"]. Never allow "none".',
  },

  // Unhandled Promise Rejection
  {
    id: 'unhandled-async',
    title: 'Async Route Handler Without Error Handling',
    pattern: /\.(get|post|put|patch|delete)\s*\(\s*['"][^'"]+['"]\s*,\s*async\s/,
    antiPattern: /try\s*\{|\.catch\(|asyncHandler|express-async-errors|express-async-handler/i,
    fileTypes: ['.js', '.ts'],
    severity: 'medium',
    description: 'Async Express route handlers without try/catch will crash the server on unhandled rejections.',
    recommendation: 'Wrap async handlers in try/catch, use express-async-errors, or create an asyncHandler wrapper.',
    fileScope: true,
  },

  // ReDoS - Regular Expression Denial of Service (CWE-1333)
  {
    id: 'redos-risk',
    title: 'Potential ReDoS Vulnerability',
    pattern: /new\s+RegExp\s*\([^)]*(?:req\.|request\.|params\.|query\.|body\.)/,
    fileTypes: ['.js', '.ts'],
    severity: 'high',
    description: 'User input is used to construct a regular expression. Malicious patterns can cause catastrophic backtracking, freezing the server.',
    recommendation: 'Never build regexes from user input. If needed, escape special characters with a library like escape-string-regexp and set a timeout.',
  },

  // Insecure Deserialization - JSON.parse with user input and no validation
  {
    id: 'unsafe-json-parse',
    title: 'JSON.parse Without Validation',
    pattern: /JSON\.parse\s*\(\s*(?:req\.|request\.|body|params|query)/,
    fileTypes: ['.js', '.ts'],
    severity: 'medium',
    description: 'Parsing user-provided JSON without schema validation can lead to unexpected object structures and prototype pollution.',
    recommendation: 'Validate parsed JSON against a schema using Zod, Joi, or ajv before using it.',
  },

  // Python subprocess with shell=True
  {
    id: 'python-subprocess-shell',
    title: 'subprocess with shell=True',
    pattern: /subprocess\.(?:call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True/,
    fileTypes: ['.py'],
    severity: 'high',
    description: 'subprocess with shell=True is vulnerable to command injection if user input is included.',
    recommendation: 'Use subprocess.run() with a list of arguments and shell=False (default).',
  },

  // Python format string injection
  {
    id: 'python-format-injection',
    title: 'Potential Format String Injection',
    pattern: /\.format\s*\(\s*(?:request\.|args\.|kwargs|user_input)/,
    fileTypes: ['.py'],
    severity: 'medium',
    description: 'Python format strings with user input can leak sensitive data via attribute access (e.g., {0.__class__}).',
    recommendation: 'Use f-strings with validated input only, or use a template engine with sandboxing.',
  },

  // Hardcoded IP / localhost in production code
  {
    id: 'hardcoded-localhost',
    title: 'Hardcoded Localhost/IP Address',
    pattern: /['"](?:http:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0))[:'"/]/,
    fileTypes: ['.js', '.ts', '.jsx', '.tsx', '.py'],
    severity: 'medium',
    description: 'Hardcoded localhost or IP address found. This will break in production and may indicate a development-only configuration left in code.',
    recommendation: 'Use environment variables for host configuration. Remove hardcoded localhost references before deploying.',
  },

  // Missing Authorization on routes
  {
    id: 'missing-auth-middleware',
    title: 'Route Without Authentication Middleware',
    pattern: /\.(get|post|put|patch|delete)\s*\(\s*['"]\/(?:api|users?|account|settings|profile|dashboard|billing|payment)/i,
    antiPattern: /(?:auth|authenticate|authorize|protect|guard|verify|middleware|jwt|session|passport|isAuthenticated|requireAuth|ensureAuth)\s*[,(]/i,
    fileTypes: ['.js', '.ts'],
    severity: 'high',
    description: 'Sensitive route appears to lack authentication middleware. Users may access protected resources without logging in.',
    recommendation: 'Add authentication middleware to all sensitive routes. Use a consistent pattern like router.use(authMiddleware) for route groups.',
    fileScope: true,
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
