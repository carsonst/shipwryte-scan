// Web URL scanner — passive security checks against live websites
// No fuzzing, no brute force, no auth bypass — safe and legal

const SCANNER_NAME = 'shipwryte-web';

// Security headers every site should have
const REQUIRED_HEADERS = [
  {
    header: 'strict-transport-security',
    severity: 'high',
    title: 'Missing HSTS header',
    description: 'The site does not set Strict-Transport-Security. Browsers may allow HTTP connections, enabling man-in-the-middle attacks.',
    recommendation: 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains to your server response headers.',
  },
  {
    header: 'content-security-policy',
    severity: 'medium',
    title: 'Missing Content-Security-Policy header',
    description: 'No CSP header found. Without CSP, the browser has no restrictions on resource loading, making XSS attacks easier to exploit.',
    recommendation: 'Add a Content-Security-Policy header. Start with a report-only policy to avoid breaking your site.',
  },
  {
    header: 'x-content-type-options',
    severity: 'medium',
    title: 'Missing X-Content-Type-Options header',
    description: 'Without this header, browsers may MIME-sniff responses, potentially interpreting uploads or API responses as executable content.',
    recommendation: 'Add X-Content-Type-Options: nosniff to all responses.',
  },
  {
    header: 'x-frame-options',
    severity: 'medium',
    title: 'Missing clickjacking protection',
    description: 'No X-Frame-Options or CSP frame-ancestors directive found. The site can be embedded in iframes on any domain, enabling clickjacking.',
    recommendation: 'Add X-Frame-Options: DENY (or SAMEORIGIN) or use CSP frame-ancestors directive.',
    check: (headers) => {
      // Also satisfied by CSP frame-ancestors
      const csp = headers.get('content-security-policy') || '';
      return headers.has('x-frame-options') || csp.includes('frame-ancestors');
    },
  },
  {
    header: 'referrer-policy',
    severity: 'low',
    title: 'Missing Referrer-Policy header',
    description: 'Without a Referrer-Policy, the browser sends the full URL (including query params) to external sites, potentially leaking sensitive data.',
    recommendation: 'Add Referrer-Policy: strict-origin-when-cross-origin (or stricter).',
  },
  {
    header: 'permissions-policy',
    severity: 'low',
    title: 'Missing Permissions-Policy header',
    description: 'No Permissions-Policy (formerly Feature-Policy) header found. Browser features like camera, microphone, and geolocation are unrestricted.',
    recommendation: 'Add a Permissions-Policy header to restrict unnecessary browser features.',
  },
];

// Headers that leak server info
const LEAKY_HEADERS = [
  {
    header: 'server',
    severity: 'low',
    title: 'Server header exposes software version',
    description: 'The Server header reveals the web server software and version, helping attackers target known vulnerabilities.',
    recommendation: 'Remove or genericize the Server header in your web server configuration.',
    check: (value) => /\d/.test(value), // only flag if it contains a version number
  },
  {
    header: 'x-powered-by',
    severity: 'low',
    title: 'X-Powered-By header exposes technology stack',
    description: 'The X-Powered-By header reveals the backend framework (e.g., Express, PHP), giving attackers information about your stack.',
    recommendation: 'Remove the X-Powered-By header. In Express, use helmet or app.disable("x-powered-by").',
    check: () => true, // always flag if present
  },
  {
    header: 'x-aspnet-version',
    severity: 'low',
    title: 'X-AspNet-Version header exposes .NET version',
    description: 'This header reveals the ASP.NET version, which can be used to target version-specific vulnerabilities.',
    recommendation: 'Disable this header in your web.config or IIS configuration.',
    check: () => true,
  },
];

// Sensitive paths to probe
const SENSITIVE_PATHS = [
  { path: '/.env', severity: 'critical', title: 'Exposed .env file', description: '.env file is publicly accessible. This typically contains database credentials, API keys, and other secrets.' },
  { path: '/.git/config', severity: 'critical', title: 'Exposed .git directory', description: 'The .git directory is publicly accessible. Attackers can download the full source code and commit history, including any secrets ever committed.' },
  { path: '/.git/HEAD', severity: 'critical', title: 'Exposed .git directory', description: 'The .git/HEAD file is accessible, confirming the .git directory is exposed.' },
  { path: '/.env.local', severity: 'critical', title: 'Exposed .env.local file', description: '.env.local file is publicly accessible, likely containing local secrets and API keys.' },
  { path: '/.env.production', severity: 'critical', title: 'Exposed .env.production file', description: 'Production environment file is publicly accessible, likely containing production secrets.' },
  { path: '/wp-admin/', severity: 'medium', title: 'WordPress admin panel exposed', description: 'The WordPress admin login page is publicly accessible. This is a common target for brute-force attacks.', checkBody: (body) => body.includes('wp-login') || body.includes('WordPress') || body.includes('wp-admin') },
  { path: '/phpinfo.php', severity: 'high', title: 'phpinfo() page exposed', description: 'A phpinfo page is publicly accessible, revealing PHP configuration, server paths, and installed modules.', checkBody: (body) => body.includes('phpinfo') || body.includes('PHP Version') },
  { path: '/server-status', severity: 'medium', title: 'Apache server-status exposed', description: 'Apache server-status page is accessible, leaking active connections, request details, and server load.', checkBody: (body) => body.includes('Apache Server Status') || body.includes('Server uptime') },
  { path: '/debug', severity: 'medium', title: 'Debug endpoint exposed', description: 'A /debug endpoint is accessible in production. Debug pages often leak internal state, stack traces, and configuration.', checkBody: (body) => body.includes('debug') && !body.includes('<!doctype') },
  { path: '/.DS_Store', severity: 'low', title: 'macOS .DS_Store file exposed', description: '.DS_Store file is accessible, potentially revealing directory structure and file names.' },
  { path: '/api/docs', severity: 'low', title: 'API documentation publicly accessible', description: 'API documentation endpoint is publicly accessible. While useful for developers, it reveals all API endpoints and parameters to potential attackers.' },
  { path: '/swagger.json', severity: 'low', title: 'Swagger/OpenAPI spec exposed', description: 'The OpenAPI spec file is publicly accessible, revealing your entire API surface area.' },
  { path: '/graphql', severity: 'low', title: 'GraphQL endpoint found', description: 'A GraphQL endpoint is accessible. If introspection is enabled, the full schema (types, queries, mutations) is exposed.', checkBody: (body) => body.includes('"data"') || body.includes('"errors"') || body.includes('GraphQL') },
  { path: '/.well-known/security.txt', severity: 'info', skip: true }, // This is actually good — we check for its absence
  { path: '/robots.txt', severity: 'info', skip: true }, // Analyzed separately
];

// Check cookie security
function checkCookies(headers) {
  const findings = [];
  const setCookies = headers.getSetCookie?.() || [];

  for (const cookie of setCookies) {
    const name = cookie.split('=')[0]?.trim() || 'unknown';
    const lower = cookie.toLowerCase();

    if (!lower.includes('secure')) {
      findings.push({
        scanner: SCANNER_NAME,
        severity: 'medium',
        category: 'config',
        title: `Cookie "${name}" missing Secure flag`,
        description: `The "${name}" cookie is not marked Secure, so it can be sent over unencrypted HTTP connections.`,
        file: null,
        line: null,
        recommendation: 'Add the Secure flag to all cookies, especially session cookies.',
      });
    }

    if (!lower.includes('httponly') && isSessionCookie(name)) {
      findings.push({
        scanner: SCANNER_NAME,
        severity: 'medium',
        category: 'config',
        title: `Session cookie "${name}" missing HttpOnly flag`,
        description: `The "${name}" cookie appears to be a session cookie but is not marked HttpOnly, making it accessible to JavaScript and vulnerable to XSS-based session theft.`,
        file: null,
        line: null,
        recommendation: 'Add the HttpOnly flag to session cookies to prevent JavaScript access.',
      });
    }

    if (!lower.includes('samesite')) {
      findings.push({
        scanner: SCANNER_NAME,
        severity: 'low',
        category: 'config',
        title: `Cookie "${name}" missing SameSite attribute`,
        description: `The "${name}" cookie does not set a SameSite attribute. Modern browsers default to Lax, but explicitly setting it prevents CSRF in older browsers.`,
        file: null,
        line: null,
        recommendation: 'Add SameSite=Lax (or Strict) to all cookies.',
      });
    }
  }

  return findings;
}

function isSessionCookie(name) {
  const lower = name.toLowerCase();
  return ['session', 'sess', 'sid', 'token', 'auth', 'jwt', 'access', 'refresh', 'csrf', 'xsrf'].some(k => lower.includes(k));
}

// Check CORS headers
function checkCORS(headers) {
  const findings = [];
  const acao = headers.get('access-control-allow-origin');
  const acac = headers.get('access-control-allow-credentials');

  if (acao === '*') {
    if (acac === 'true') {
      findings.push({
        scanner: SCANNER_NAME,
        severity: 'critical',
        category: 'config',
        title: 'CORS: wildcard origin with credentials',
        description: 'The server allows any origin with credentials. This means any website can make authenticated requests to your API and read the responses.',
        file: null,
        line: null,
        recommendation: 'Never combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. Whitelist specific origins.',
      });
    } else {
      findings.push({
        scanner: SCANNER_NAME,
        severity: 'low',
        category: 'config',
        title: 'CORS: wildcard origin',
        description: 'The server allows any origin. This is fine for public APIs but may expose internal endpoints to cross-origin requests.',
        file: null,
        line: null,
        recommendation: 'If the API is not fully public, restrict Access-Control-Allow-Origin to specific trusted domains.',
      });
    }
  }

  return findings;
}

// Check for mixed content in HTML
function checkMixedContent(body, url) {
  const findings = [];
  if (!url.startsWith('https://')) return findings;

  const httpResources = body.match(/(?:src|href|action)=["']http:\/\/[^"']+["']/gi) || [];
  const filtered = httpResources.filter(r => !r.includes('http://schemas.') && !r.includes('http://www.w3.org/'));

  if (filtered.length > 0) {
    findings.push({
      scanner: SCANNER_NAME,
      severity: 'medium',
      category: 'config',
      title: `Mixed content: ${filtered.length} HTTP resource(s) on HTTPS page`,
      description: `The page loads ${filtered.length} resource(s) over plain HTTP. Browsers may block these or show security warnings. Examples: ${filtered.slice(0, 3).join(', ')}`,
      file: null,
      line: null,
      recommendation: 'Load all resources over HTTPS. Replace http:// URLs with https:// or use protocol-relative URLs.',
    });
  }

  return findings;
}

// Check robots.txt for sensitive paths
function analyzeRobotsTxt(body) {
  const findings = [];
  const lines = body.split('\n');
  const disallowed = lines
    .filter(l => l.trim().toLowerCase().startsWith('disallow:'))
    .map(l => l.split(':').slice(1).join(':').trim())
    .filter(Boolean);

  const sensitivePatterns = ['/admin', '/api', '/internal', '/secret', '/private', '/dashboard', '/panel', '/staging', '/backup', '/db', '/config', '/debug'];
  const exposed = disallowed.filter(path =>
    sensitivePatterns.some(p => path.toLowerCase().includes(p))
  );

  if (exposed.length > 0) {
    findings.push({
      scanner: SCANNER_NAME,
      severity: 'low',
      category: 'config',
      title: 'robots.txt reveals sensitive paths',
      description: `robots.txt disallows paths that suggest sensitive areas: ${exposed.slice(0, 5).join(', ')}. While robots.txt is meant for search engines, it acts as a directory for attackers.`,
      file: null,
      line: null,
      recommendation: 'Use authentication and authorization to protect sensitive paths rather than relying on robots.txt exclusion.',
    });
  }

  return findings;
}

// Check if security.txt exists (good practice per RFC 9116)
function checkSecurityTxt(exists) {
  if (!exists) {
    return [{
      scanner: SCANNER_NAME,
      severity: 'low',
      category: 'config',
      title: 'No security.txt file found',
      description: 'No /.well-known/security.txt found. This file (RFC 9116) tells security researchers how to report vulnerabilities to your organization.',
      file: null,
      line: null,
      recommendation: 'Create a /.well-known/security.txt with contact info, preferred languages, and disclosure policy.',
    }];
  }
  return [];
}

// Check SSL/redirect behavior
async function checkSSL(url) {
  const findings = [];

  // If the user gave an HTTPS URL, check that HTTP redirects to HTTPS
  if (url.startsWith('https://')) {
    const httpUrl = url.replace('https://', 'http://');
    try {
      const res = await fetch(httpUrl, {
        method: 'HEAD',
        redirect: 'manual',
        signal: AbortSignal.timeout(5000),
      });
      const location = res.headers.get('location') || '';
      if (!location.startsWith('https://')) {
        findings.push({
          scanner: SCANNER_NAME,
          severity: 'high',
          category: 'config',
          title: 'HTTP does not redirect to HTTPS',
          description: 'Requesting the HTTP version of the site does not redirect to HTTPS. Users who type the domain without https:// will use an unencrypted connection.',
          file: null,
          line: null,
          recommendation: 'Configure your server to redirect all HTTP traffic to HTTPS with a 301 redirect.',
        });
      }
    } catch {
      // HTTP version might not exist — that's fine
    }
  }

  return findings;
}

async function safeFetch(url, options = {}) {
  try {
    return await fetch(url, {
      ...options,
      redirect: 'follow',
      signal: AbortSignal.timeout(options.timeout || 8000),
      headers: {
        'User-Agent': 'Shipwryte-Scan/0.3.0 (security scanner; +https://shipwryte.com)',
        ...options.headers,
      },
    });
  } catch {
    return null;
  }
}

export async function runWebScanner(targetUrl) {
  const findings = [];

  // Normalize URL
  let url = targetUrl.trim();
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = 'https://' + url;
  }
  url = url.replace(/\/+$/, '');

  // 1. Fetch the main page
  const mainRes = await safeFetch(url);
  if (!mainRes) {
    throw new Error(`Could not reach ${url}. Make sure the URL is correct and the site is up.`);
  }

  const headers = mainRes.headers;
  const body = await mainRes.text();

  // 2. Check security headers
  for (const rule of REQUIRED_HEADERS) {
    if (rule.check) {
      if (!rule.check(headers)) {
        findings.push({
          scanner: SCANNER_NAME,
          severity: rule.severity,
          category: 'config',
          title: rule.title,
          description: rule.description,
          file: null,
          line: null,
          recommendation: rule.recommendation,
        });
      }
    } else if (!headers.has(rule.header)) {
      findings.push({
        scanner: SCANNER_NAME,
        severity: rule.severity,
        category: 'config',
        title: rule.title,
        description: rule.description,
        file: null,
        line: null,
        recommendation: rule.recommendation,
      });
    }
  }

  // 3. Check leaky headers
  for (const rule of LEAKY_HEADERS) {
    const value = headers.get(rule.header);
    if (value && rule.check(value)) {
      findings.push({
        scanner: SCANNER_NAME,
        severity: rule.severity,
        category: 'config',
        title: rule.title,
        description: `${rule.description} Current value: "${value}"`,
        file: null,
        line: null,
        recommendation: rule.recommendation,
      });
    }
  }

  // 4. Check cookies
  findings.push(...checkCookies(headers));

  // 5. Check CORS
  findings.push(...checkCORS(headers));

  // 6. Check mixed content
  findings.push(...checkMixedContent(body, url));

  // 7. Check SSL/redirect
  findings.push(...(await checkSSL(url)));

  // 8. Probe sensitive paths (in parallel)
  // First, fetch a known-bad path to get the "soft 404" baseline
  const baseline404 = await safeFetch(`${url}/__shipwryte_404_check_${Date.now()}__`, { timeout: 5000 });
  const baseline404Body = baseline404 ? await baseline404.text().catch(() => '') : '';
  const baseline404Length = baseline404Body.length;

  const pathChecks = SENSITIVE_PATHS.filter(p => !p.skip);
  const pathResults = await Promise.all(
    pathChecks.map(async (probe) => {
      const res = await safeFetch(`${url}${probe.path}`, { method: 'GET', timeout: 5000 });
      if (!res) return null;
      if (res.status === 200) {
        const resBody = await res.text().catch(() => '');
        // If the probe has a body check, use it as the sole validator
        if (probe.checkBody) {
          if (!probe.checkBody(resBody)) return null;
        } else {
          // Skip tiny responses that are likely empty/placeholder
          if (resBody.length < 10) return null;
          // Skip HTML pages — .env, .git/config etc. should never return HTML
          if (resBody.trimStart().startsWith('<!') || resBody.trimStart().startsWith('<html')) return null;
          // Skip responses that match the soft-404 baseline (SPA catch-all)
          if (baseline404Length > 0 && Math.abs(resBody.length - baseline404Length) < 100) return null;
        }

        return {
          scanner: SCANNER_NAME,
          severity: probe.severity,
          category: probe.severity === 'critical' ? 'secret' : 'config',
          title: probe.title,
          description: probe.description,
          file: probe.path,
          line: null,
          recommendation: `Remove or restrict access to ${probe.path}. Ensure it is not served by your web server.`,
        };
      }
      return null;
    })
  );
  findings.push(...pathResults.filter(Boolean));

  // 9. Check robots.txt
  const robotsRes = await safeFetch(`${url}/robots.txt`, { timeout: 5000 });
  if (robotsRes && robotsRes.status === 200) {
    const robotsBody = await robotsRes.text().catch(() => '');
    if (robotsBody && !robotsBody.includes('<!DOCTYPE')) {
      findings.push(...analyzeRobotsTxt(robotsBody));
    }
  }

  // 10. Check security.txt
  const secTxtRes = await safeFetch(`${url}/.well-known/security.txt`, { timeout: 5000 });
  const hasSecurityTxt = secTxtRes && secTxtRes.status === 200;
  findings.push(...checkSecurityTxt(hasSecurityTxt));

  return findings;
}
