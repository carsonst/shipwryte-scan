import path from 'path';
import chalk from 'chalk';
import ora from 'ora';
import { runSecretScanner } from './scanners/secrets.js';
import { runDependencyScanner } from './scanners/dependencies.js';
import { runSASTScanner } from './scanners/sast.js';
import { calculateScore, categorizeSeverity } from './scoring.js';
import { generateMarkdownReport } from './reporters/markdown.js';
import { generateHTMLReport } from './reporters/html.js';
import { writeFileSync } from 'fs';

export async function runScan(targetPath, options = {}) {
  const absPath = path.resolve(targetPath);
  const findings = [];
  const scanStart = Date.now();

  // Run scanners
  if (options.secrets !== false) {
    const spinner = ora({ text: '  Scanning for hardcoded secrets...', color: 'yellow' }).start();
    try {
      const secretFindings = await runSecretScanner(absPath);
      findings.push(...secretFindings);
      spinner.succeed(`  Secrets scan complete — ${secretFindings.length} finding(s)`);
    } catch (err) {
      spinner.warn(`  Secrets scan skipped: ${err.message}`);
    }
  }

  if (options.deps !== false) {
    const spinner = ora({ text: '  Scanning dependencies for known CVEs...', color: 'yellow' }).start();
    try {
      const depFindings = await runDependencyScanner(absPath);
      findings.push(...depFindings);
      spinner.succeed(`  Dependency scan complete — ${depFindings.length} finding(s)`);
    } catch (err) {
      spinner.warn(`  Dependency scan skipped: ${err.message}`);
    }
  }

  if (options.sast !== false) {
    const spinner = ora({ text: '  Running static analysis...', color: 'yellow' }).start();
    try {
      const sastFindings = await runSASTScanner(absPath);
      findings.push(...sastFindings);
      spinner.succeed(`  Static analysis complete — ${sastFindings.length} finding(s)`);
    } catch (err) {
      spinner.warn(`  Static analysis skipped: ${err.message}`);
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

  // Output
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

  // JSON output to stdout
  if (options.json) {
    const result = { score, counts, findings: filtered, scanDuration };
    console.log(JSON.stringify(result, null, 2));
    return result;
  }

  // Generate report file
  const format = options.output || 'markdown';
  const ext = format === 'markdown' ? 'md' : format === 'html' ? 'html' : 'json';
  const outputFile = options.file || `shipwryte-report.${ext}`;

  let reportContent;
  if (format === 'json') {
    reportContent = JSON.stringify({ score, counts, findings: filtered, scanDuration }, null, 2);
  } else if (format === 'html') {
    reportContent = generateHTMLReport({ score, counts, findings: filtered, scanDuration, targetPath: absPath });
  } else {
    reportContent = generateMarkdownReport({ score, counts, findings: filtered, scanDuration, targetPath: absPath });
  }

  writeFileSync(outputFile, reportContent, 'utf-8');
  console.log(chalk.cyan(`\n  📄 Report saved to ${outputFile}`));
  console.log('');

  return { score, counts, findings: filtered, scanDuration };
}
