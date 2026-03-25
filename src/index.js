import path from 'path';
import chalk from 'chalk';
import ora from 'ora';
import { runSecretScanner } from './scanners/secrets.js';
import { runDependencyScanner } from './scanners/dependencies.js';
import { runSASTScanner } from './scanners/sast.js';
import { calculateScore, categorizeSeverity } from './scoring.js';
import { generateMarkdownReport } from './reporters/markdown.js';
import { generateHTMLReport } from './reporters/html.js';
import { writeFileSync, readdirSync, statSync } from 'fs';

const COUNT_EXTENSIONS = new Set([
  '.js', '.ts', '.jsx', '.tsx', '.py', '.go', '.rb', '.java',
  '.env', '.yaml', '.yml', '.json', '.toml', '.cfg', '.conf',
  '.properties', '.sh', '.sql', '.tf',
]);
const COUNT_IGNORE = new Set([
  'node_modules', '.git', 'dist', 'build', '.next', '__pycache__',
  'venv', '.venv', 'vendor', '.cache', 'coverage',
  'test', 'tests', '__tests__', '__mocks__', 'fixtures',
]);

function countFiles(dir, depth = 10) {
  if (depth <= 0) return 0;
  let count = 0;
  try {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (entry.name.startsWith('.') && !entry.name.startsWith('.env')) continue;
      if (COUNT_IGNORE.has(entry.name)) continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        count += countFiles(full, depth - 1);
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (COUNT_EXTENSIONS.has(ext) || entry.name.startsWith('.env')) count++;
      }
    }
  } catch {}
  return count;
}

export async function runScan(targetPath, options = {}) {
  const absPath = path.resolve(targetPath);
  const findings = [];
  const scanStart = Date.now();
  const silent = options.json || options.quiet;

  // Run scanners
  if (options.secrets !== false) {
    const spinner = silent ? null : ora({ text: '  Scanning for hardcoded secrets...', color: 'yellow' }).start();
    try {
      const secretFindings = await runSecretScanner(absPath);
      findings.push(...secretFindings);
      spinner?.succeed(`  Secrets scan complete — ${secretFindings.length} finding(s)`);
    } catch (err) {
      spinner?.warn(`  Secrets scan skipped: ${err.message}`);
    }
  }

  if (options.deps !== false) {
    const spinner = silent ? null : ora({ text: '  Scanning dependencies for known CVEs...', color: 'yellow' }).start();
    try {
      const depFindings = await runDependencyScanner(absPath);
      findings.push(...depFindings);
      spinner?.succeed(`  Dependency scan complete — ${depFindings.length} finding(s)`);
    } catch (err) {
      spinner?.warn(`  Dependency scan skipped: ${err.message}`);
    }
  }

  if (options.sast !== false) {
    const spinner = silent ? null : ora({ text: '  Running static analysis...', color: 'yellow' }).start();
    try {
      const sastFindings = await runSASTScanner(absPath);
      findings.push(...sastFindings);
      spinner?.succeed(`  Static analysis complete — ${sastFindings.length} finding(s)`);
    } catch (err) {
      spinner?.warn(`  Static analysis skipped: ${err.message}`);
    }
  }

  const scanDuration = ((Date.now() - scanStart) / 1000).toFixed(1);

  // Filter by severity
  const severityOrder = ['critical', 'high', 'medium', 'low'];
  const minIndex = severityOrder.indexOf(options.severity || 'low');
  const filtered = findings.filter(f => {
    const idx = severityOrder.indexOf(f.severity);
    return idx >= 0 && idx <= minIndex;
  });

  // Calculate score
  const score = calculateScore(filtered);
  const counts = categorizeSeverity(filtered);

  // Grade
  let grade = 'F';
  if (score >= 90) grade = 'A';
  else if (score >= 80) grade = 'B';
  else if (score >= 70) grade = 'C';
  else if (score >= 60) grade = 'D';

  const scannedFiles = countFiles(absPath);
  const result = { score, grade, counts, findings: filtered, scannedFiles, duration: parseFloat(scanDuration) };

  // JSON output to stdout — print ONLY JSON, nothing else
  if (options.json) {
    process.stdout.write(JSON.stringify(result, null, 2));
    return result;
  }

  // Interactive output
  if (!options.quiet) {
    console.log('');
    console.log(chalk.bold('  Results'));
    console.log(chalk.gray('  ─────────────────────────────'));

    const scoreColor = score >= 80 ? 'green' : score >= 60 ? 'yellow' : 'red';
    console.log(`  Security Score: ${chalk[scoreColor].bold(score + '/100')}`);
    console.log('');

    if (counts.critical > 0) console.log(chalk.red(`  🔴 Critical: ${counts.critical}`));
    if (counts.high > 0) console.log(chalk.redBright(`  🟠 High: ${counts.high}`));
    if (counts.medium > 0) console.log(chalk.yellow(`  🟡 Medium: ${counts.medium}`));
    if (counts.low > 0) console.log(chalk.gray(`  🔵 Low: ${counts.low}`));
    if (filtered.length === 0) console.log(chalk.green('  ✅ No issues found!'));

    console.log(chalk.gray(`\n  Scanned in ${scanDuration}s`));
  }

  // Generate report file (skip in quiet mode)
  if (!options.quiet) {
    const format = options.output || 'markdown';
    const ext = format === 'markdown' ? 'md' : format === 'html' ? 'html' : 'json';
    const outputFile = options.file || `shipwryte-report.${ext}`;

    let reportContent;
    if (format === 'json') {
      reportContent = JSON.stringify(result, null, 2);
    } else if (format === 'html') {
      reportContent = generateHTMLReport({ score, counts, findings: filtered, scanDuration, targetPath: absPath });
    } else {
      reportContent = generateMarkdownReport({ score, counts, findings: filtered, scanDuration, targetPath: absPath });
    }

    writeFileSync(outputFile, reportContent, 'utf-8');
    console.log(chalk.cyan(`\n  📄 Report saved to ${outputFile}`));
    console.log('');
  }

  return result;
}
