const SEVERITY_WEIGHTS = {
  critical: 20,
  high: 10,
  medium: 4,
  low: 1,
};

// Secrets are weighted higher — a leaked key is immediately exploitable
const CATEGORY_MULTIPLIERS = {
  secret: 1.5,
  code: 1.0,
  config: 0.8,
  dependency: 0.9,
};

export function calculateScore(findings) {
  if (findings.length === 0) return 100;

  let totalPenalty = 0;

  for (const f of findings) {
    const base = SEVERITY_WEIGHTS[f.severity] || 1;
    const multiplier = CATEGORY_MULTIPLIERS[f.category] || 1.0;
    totalPenalty += base * multiplier;
  }

  // Diminishing returns — first few findings hit hardest,
  // prevents score from being 0 on any non-trivial codebase
  const adjustedPenalty = totalPenalty * (1 - Math.min(0.4, findings.length * 0.01));

  const score = Math.max(0, Math.round(100 - adjustedPenalty));
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
