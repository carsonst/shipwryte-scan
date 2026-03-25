const SEVERITY_WEIGHTS = {
  critical: 15,
  high: 8,
  medium: 3,
  low: 1,
};

export function calculateScore(findings) {
  if (findings.length === 0) return 100;

  let totalPenalty = 0;

  for (const f of findings) {
    totalPenalty += SEVERITY_WEIGHTS[f.severity] || 1;
  }

  // Score starts at 100, penalties reduce it
  // Cap penalty so score doesn't go below 0
  const score = Math.max(0, Math.round(100 - totalPenalty));
  return score;
}

export function categorizeSeverity(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) {
    if (counts[f.severity] !== undefined) {
      counts[f.severity]++;
    }
  }
  return counts;
}

export function getScoreEmoji(score) {
  if (score >= 90) return 'A+';
  if (score >= 80) return 'A';
  if (score >= 70) return 'B';
  if (score >= 60) return 'C';
  if (score >= 50) return 'D';
  return 'F';
}

export function getScoreColor(score) {
  if (score >= 80) return '#22c55e';
  if (score >= 60) return '#eab308';
  if (score >= 40) return '#f97316';
  return '#ef4444';
}
