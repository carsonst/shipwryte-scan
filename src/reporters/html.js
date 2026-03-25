import { getScoreEmoji, getScoreColor } from '../scoring.js';

export function generateHTMLReport({ score, counts, findings, scanDuration, targetPath }) {
  const grade = getScoreEmoji(score);
  const date = new Date().toISOString().split('T')[0];
  const totalIssues = findings.length;
  const scoreColor = getScoreColor(score);

  const severityColors = {
    critical: '#ef4444',
    high: '#f97316',
    medium: '#eab308',
    low: '#3b82f6',
  };

  const findingsHTML = findings.map(f => `
    <div class="finding finding-${f.severity}">
      <div class="finding-header">
        <span class="severity-badge severity-${f.severity}">${f.severity.toUpperCase()}</span>
        <span class="finding-title">${escapeHTML(f.title)}</span>
      </div>
      <p class="finding-desc">${escapeHTML(f.description)}</p>
      ${f.file ? `<p class="finding-location"><code>${escapeHTML(f.file)}${f.line ? `:${f.line}` : ''}</code></p>` : ''}
      <p class="finding-rec"><strong>Fix:</strong> ${escapeHTML(f.recommendation)}</p>
    </div>
  `).join('\n');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Shipwryte Security Report — Score: ${score}/100</title>
  <meta name="description" content="Security scan results: ${totalIssues} issues found. Score: ${score}/100.">
  <meta property="og:title" content="Shipwryte Security Report — ${score}/100 (${grade})">
  <meta property="og:description" content="${totalIssues} security issues found. ${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low.">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #0a0a0a;
      color: #e5e5e5;
      line-height: 1.6;
    }
    .container { max-width: 800px; margin: 0 auto; padding: 40px 20px; }
    .header {
      text-align: center;
      margin-bottom: 40px;
    }
    .logo {
      font-size: 14px;
      text-transform: uppercase;
      letter-spacing: 3px;
      color: #06b6d4;
      margin-bottom: 24px;
    }
    .score-circle {
      width: 160px;
      height: 160px;
      border-radius: 50%;
      border: 6px solid ${scoreColor};
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      margin: 0 auto 16px;
    }
    .score-number {
      font-size: 48px;
      font-weight: 700;
      color: ${scoreColor};
      line-height: 1;
    }
    .score-label {
      font-size: 14px;
      color: #a3a3a3;
    }
    .score-grade {
      font-size: 20px;
      color: ${scoreColor};
      font-weight: 600;
      margin-bottom: 8px;
    }
    .meta {
      color: #737373;
      font-size: 13px;
      margin-bottom: 4px;
    }
    .summary-cards {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 12px;
      margin-bottom: 40px;
    }
    .summary-card {
      background: #171717;
      border-radius: 8px;
      padding: 16px;
      text-align: center;
      border-left: 3px solid;
    }
    .summary-card.critical { border-color: ${severityColors.critical}; }
    .summary-card.high { border-color: ${severityColors.high}; }
    .summary-card.medium { border-color: ${severityColors.medium}; }
    .summary-card.low { border-color: ${severityColors.low}; }
    .summary-count {
      font-size: 28px;
      font-weight: 700;
    }
    .summary-label {
      font-size: 12px;
      color: #737373;
      text-transform: uppercase;
      letter-spacing: 1px;
    }
    .findings-section { margin-bottom: 40px; }
    .section-title {
      font-size: 18px;
      font-weight: 600;
      margin-bottom: 16px;
      padding-bottom: 8px;
      border-bottom: 1px solid #262626;
    }
    .finding {
      background: #171717;
      border-radius: 8px;
      padding: 16px;
      margin-bottom: 12px;
      border-left: 3px solid;
    }
    .finding-critical { border-color: ${severityColors.critical}; }
    .finding-high { border-color: ${severityColors.high}; }
    .finding-medium { border-color: ${severityColors.medium}; }
    .finding-low { border-color: ${severityColors.low}; }
    .finding-header {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 8px;
    }
    .severity-badge {
      font-size: 10px;
      font-weight: 700;
      padding: 2px 8px;
      border-radius: 4px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .severity-critical { background: ${severityColors.critical}22; color: ${severityColors.critical}; }
    .severity-high { background: ${severityColors.high}22; color: ${severityColors.high}; }
    .severity-medium { background: ${severityColors.medium}22; color: ${severityColors.medium}; }
    .severity-low { background: ${severityColors.low}22; color: ${severityColors.low}; }
    .finding-title { font-weight: 600; }
    .finding-desc { color: #a3a3a3; font-size: 14px; margin-bottom: 8px; }
    .finding-location { font-size: 13px; margin-bottom: 8px; }
    .finding-location code {
      background: #262626;
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 12px;
    }
    .finding-rec {
      font-size: 13px;
      color: #a3a3a3;
    }
    .cta-section {
      background: linear-gradient(135deg, #0e7490, #0891b2);
      border-radius: 12px;
      padding: 32px;
      text-align: center;
      margin-top: 40px;
    }
    .cta-section h2 {
      font-size: 24px;
      margin-bottom: 12px;
    }
    .cta-section p {
      color: #cffafe;
      margin-bottom: 20px;
      font-size: 15px;
    }
    .cta-button {
      display: inline-block;
      background: white;
      color: #0e7490;
      font-weight: 700;
      padding: 12px 32px;
      border-radius: 8px;
      text-decoration: none;
      font-size: 16px;
      transition: transform 0.2s;
    }
    .cta-button:hover { transform: scale(1.05); }
    .footer {
      text-align: center;
      margin-top: 40px;
      color: #525252;
      font-size: 13px;
    }
    .footer a { color: #06b6d4; text-decoration: none; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="logo">Shipwryte Scan</div>
      <div class="score-circle">
        <div class="score-number">${score}</div>
        <div class="score-label">out of 100</div>
      </div>
      <div class="score-grade">Grade: ${grade}</div>
      <div class="meta">Scanned on ${date} in ${scanDuration}s</div>
      <div class="meta">${totalIssues} issue${totalIssues !== 1 ? 's' : ''} found</div>
    </div>

    <div class="summary-cards">
      <div class="summary-card critical">
        <div class="summary-count" style="color:${severityColors.critical}">${counts.critical}</div>
        <div class="summary-label">Critical</div>
      </div>
      <div class="summary-card high">
        <div class="summary-count" style="color:${severityColors.high}">${counts.high}</div>
        <div class="summary-label">High</div>
      </div>
      <div class="summary-card medium">
        <div class="summary-count" style="color:${severityColors.medium}">${counts.medium}</div>
        <div class="summary-label">Medium</div>
      </div>
      <div class="summary-card low">
        <div class="summary-count" style="color:${severityColors.low}">${counts.low}</div>
        <div class="summary-label">Low</div>
      </div>
    </div>

    ${totalIssues > 0 ? `
    <div class="findings-section">
      <div class="section-title">Findings</div>
      ${findingsHTML}
    </div>
    ` : `
    <div class="findings-section" style="text-align:center;padding:40px;">
      <div style="font-size:48px;margin-bottom:12px;">✅</div>
      <div style="font-size:18px;font-weight:600;">No issues found</div>
      <div style="color:#737373;margin-top:8px;">Your code looks clean!</div>
    </div>
    `}

    <div class="cta-section">
      <h2>Ready for a deeper review?</h2>
      <p>
        This automated scan caught ${totalIssues} surface-level issue${totalIssues !== 1 ? 's' : ''}.
        For a comprehensive audit including auth review, threat modeling, and business logic analysis:
      </p>
      <a href="https://shipwryte.com/audit" class="cta-button">Book a Human Audit</a>
    </div>

    <div class="footer">
      Generated by <a href="https://shipwryte.com">Shipwryte Scan</a> — Free security scanning for AI-generated code.
    </div>
  </div>
</body>
</html>`;
}

function escapeHTML(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
