'use strict';
/**
 * parse-results.js
 *
 * Reads raw JSON reports from the scan tools and normalises them into a
 * single combined-results.json that the React dashboard can consume.
 *
 * Inputs  (searched in REPORTS_DIR, default: dashboard/public/reports):
 *   npm-audit.json      — output of `npm audit --json`
 *   sonar-issues.json   — SonarCloud /api/issues/search export
 *   trivy-report.json   — Trivy JSON output
 *   zap-report.json     — OWASP ZAP JSON report
 *   pipeline-meta.json  — CI metadata injected by the workflow
 *
 * Output:
 *   results/combined-results.json  (also copied to REPORTS_DIR)
 */

const fs   = require('fs');
const path = require('path');
const { randomUUID } = require('crypto');

// ── Paths ──────────────────────────────────────────────────────────────────
const ROOT        = path.join(__dirname, '..');
const REPORTS_DIR = process.env.REPORTS_DIR
  || path.join(ROOT, 'dashboard', 'public', 'reports');
const OUTPUT_DIR  = path.join(ROOT, 'results');

fs.mkdirSync(OUTPUT_DIR, { recursive: true });

// ── Helpers ────────────────────────────────────────────────────────────────
function readJson(filename) {
  const file = path.join(REPORTS_DIR, filename);
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (_) {
    return null;
  }
}

function normSeverity(raw) {
  const s = (raw || '').toLowerCase();
  if (s === 'critical' || s === 'blocker') return 'critical';
  if (s === 'high'     || s === 'major'  ) return 'high';
  if (s === 'medium'   || s === 'moderate' || s === 'minor') return 'medium';
  if (s === 'low'      || s === 'info'   ) return 'low';
  return 'low';
}

function riskCodeToSeverity(rc) {
  const n = parseInt(rc || '0', 10);
  if (n >= 3) return 'critical';
  if (n === 2) return 'high';
  if (n === 1) return 'medium';
  return 'low';
}

function statusForSeverity(sev) {
  if (sev === 'critical') return 'blocking';
  if (sev === 'high')     return 'review';
  return 'acknowledged';
}

// ── Parsers ────────────────────────────────────────────────────────────────

function parseNpmAudit(data) {
  const findings = [];
  if (!data) return { status: 'unknown', findings };

  const vulns = data.vulnerabilities || {};
  for (const [pkgName, info] of Object.entries(vulns)) {
    const sev = normSeverity(info.severity);
    findings.push({
      id:          randomUUID(),
      title:       `Vulnerable dependency: ${pkgName}`,
      tool:        'npm audit',
      severity:    sev,
      location:    `${pkgName}@${info.version || 'unknown'}`,
      status:      statusForSeverity(sev),
      description: (info.via || [])
        .map(v => (typeof v === 'string' ? v : v.title || v.url || ''))
        .filter(Boolean)
        .join('; ') || info.fixAvailable
          ? 'Fix available via npm audit fix'
          : 'No automatic fix available',
    });
  }

  const meta = data.metadata?.vulnerabilities || {};
  const hasCritical = (meta.critical || 0) > 0;
  const hasHigh     = (meta.high     || 0) > 0;
  const status = hasCritical ? 'failed' : hasHigh ? 'warning' : findings.length ? 'warning' : 'passed';
  return { status, findings };
}

function parseSonar(data) {
  const findings = [];
  if (!data) return { status: 'unknown', findings };

  (data.issues || []).forEach(issue => {
    const sev = normSeverity(issue.severity);
    findings.push({
      id:          randomUUID(),
      title:       issue.message || issue.rule || 'SonarCloud issue',
      tool:        'SonarCloud',
      severity:    sev,
      location:    issue.component
        ? `${issue.component}:${issue.textRange?.startLine || ''}`
        : issue.component || 'unknown',
      status:      statusForSeverity(sev),
      description: `Rule: ${issue.rule || 'N/A'} | Type: ${issue.type || 'N/A'}`,
    });
  });

  const hasCritical = findings.some(f => f.severity === 'critical');
  const hasHigh     = findings.some(f => f.severity === 'high');
  const status = hasCritical ? 'failed' : hasHigh ? 'warning' : findings.length ? 'warning' : 'passed';
  return { status, findings };
}

function parseTrivy(data) {
  const findings = [];
  if (!data) return { status: 'unknown', findings };

  (data.Results || []).forEach(result => {
    (result.Vulnerabilities || []).forEach(vuln => {
      const sev = normSeverity(vuln.Severity);
      findings.push({
        id:          randomUUID(),
        title:       `${vuln.VulnerabilityID}: ${vuln.Title || vuln.PkgName}`,
        tool:        'Trivy',
        severity:    sev,
        location:    `${vuln.PkgName}@${vuln.InstalledVersion}`,
        status:      statusForSeverity(sev),
        description: vuln.Description || vuln.PrimaryURL || 'No description available',
      });
    });
  });

  const hasCritical = findings.some(f => f.severity === 'critical');
  const hasHigh     = findings.some(f => f.severity === 'high');
  const status = hasCritical ? 'failed' : hasHigh ? 'warning' : findings.length ? 'warning' : 'passed';
  return { status, findings };
}

function parseZap(data) {
  const findings = [];
  if (!data) return { status: 'unknown', findings };

  (data.site || []).forEach(site => {
    (site.alerts || []).forEach(alert => {
      const sev = riskCodeToSeverity(alert.riskcode);
      findings.push({
        id:          randomUUID(),
        title:       alert.name || alert.alert || 'ZAP alert',
        tool:        'OWASP ZAP',
        severity:    sev,
        location:    (alert.instances?.[0]?.uri) || site['@name'] || 'unknown',
        status:      statusForSeverity(sev),
        description: alert.desc
          ? alert.desc.replace(/<[^>]+>/g, '').trim()
          : 'No description available',
      });
    });
  });

  const hasCritical = findings.some(f => f.severity === 'critical');
  const hasHigh     = findings.some(f => f.severity === 'high');
  const status = hasCritical ? 'failed' : hasHigh ? 'warning' : findings.length ? 'warning' : 'passed';
  return { status, findings };
}

// ── Main ───────────────────────────────────────────────────────────────────

const meta     = readJson('pipeline-meta.json') || {};
const npmData  = readJson('npm-audit.json');
const sonarData= readJson('sonar-issues.json');
const trivyData= readJson('trivy-report.json');
const zapData  = readJson('zap-report.json');

const npm   = parseNpmAudit(npmData);
const sonar = parseSonar(sonarData);
const trivy = parseTrivy(trivyData);
const zap   = parseZap(zapData);

const allFindings = [
  ...npm.findings,
  ...sonar.findings,
  ...trivy.findings,
  ...zap.findings,
];

// Sort: critical first, then high, medium, low
const sevOrder = { critical: 0, high: 1, medium: 2, low: 3 };
allFindings.sort((a, b) => (sevOrder[a.severity] ?? 4) - (sevOrder[b.severity] ?? 4));

const summary = {
  critical: allFindings.filter(f => f.severity === 'critical').length,
  high:     allFindings.filter(f => f.severity === 'high').length,
  medium:   allFindings.filter(f => f.severity === 'medium').length,
  low:      allFindings.filter(f => f.severity === 'low').length,
  passed:   false,
};
summary.passed = summary.critical === 0;

const result = {
  runId:     meta.runNumber   || process.env.GITHUB_RUN_NUMBER || '0',
  timestamp: meta.timestamp   || new Date().toISOString(),
  commit:    meta.commit      || process.env.GITHUB_SHA        || 'local',
  branch:    meta.branch      || process.env.GITHUB_REF_NAME   || 'local',
  summary,
  tools: {
    sonarqube: { status: sonar.status, issues: sonar.findings },
    trivy:     { status: trivy.status, issues: trivy.findings  },
    zap:       { status: zap.status,   issues: zap.findings    },
    npmAudit:  { status: npm.status,   issues: npm.findings    },
  },
  findings: allFindings,
};

const outPath = path.join(OUTPUT_DIR, 'combined-results.json');
fs.writeFileSync(outPath, JSON.stringify(result, null, 2));
console.log(`[parse-results] Written: ${outPath}`);
console.log(`[parse-results] Summary: critical=${summary.critical} high=${summary.high} medium=${summary.medium} low=${summary.low} passed=${summary.passed}`);

// Also copy to dashboard/public/reports/ so the dashboard picks it up
const dashCopy = path.join(REPORTS_DIR, 'combined-results.json');
fs.writeFileSync(dashCopy, JSON.stringify(result, null, 2));
console.log(`[parse-results] Copied to: ${dashCopy}`);

// Gate: exit 1 if critical issues found (used by the CI pipeline gate step)
if (summary.critical > 0) {
  console.error(`[parse-results] GATE FAILED — ${summary.critical} critical finding(s) found.`);
  process.exit(1);
}

console.log('[parse-results] Gate passed — no critical findings.');
