import { useReport } from '../hooks/useReport';

const SEV_MAP = {
  blocker:  'critical',
  critical: 'critical',
  major:    'high',
  minor:    'medium',
  info:     'info',
};

function badgeClass(sev = '') {
  return SEV_MAP[sev.toLowerCase()] || 'info';
}

function stripComponent(c = '') {
  // 'neelp03_CMPE272-project:routes/auth.js' → 'routes/auth.js'
  return c.includes(':') ? c.split(':').slice(1).join(':') : c;
}

export default function SonarReport() {
  const { data, loading, error } = useReport('sonar-issues.json');

  if (loading) return <div className="state-box"><p>Loading SonarCloud report…</p></div>;
  if (error)   return <div className="state-box error-box"><span className="icon">⚠</span><p>{error.message}</p></div>;

  const issues = data?.issues || [];
  const total  = data?.total  || issues.length;

  // Count by severity
  const counts = issues.reduce((acc, i) => {
    const k = (i.severity || 'info').toLowerCase();
    acc[k] = (acc[k] || 0) + 1;
    return acc;
  }, {});

  const sevChips = [
    ['blocker',  '#ef4444'],
    ['critical', '#ef4444'],
    ['major',    '#f97316'],
    ['minor',    '#f59e0b'],
    ['info',     '#6b7280'],
  ].filter(([k]) => counts[k]);

  return (
    <div>
      <h2 className="section-title">SonarCloud — Static Analysis (SAST)</h2>
      <p className="section-sub">
        Code-level security vulnerabilities, bugs, and code smells detected by SonarCloud.
      </p>

      <div className="sev-row">
        {sevChips.map(([label, color]) => (
          <div className="sev-chip" key={label}>
            <span className="dot" style={{ background: color }} />
            <span className="num">{counts[label]}</span>
            <span className="lbl">{label}</span>
          </div>
        ))}
        <div className="sev-chip">
          <span className="num">{total}</span>
          <span className="lbl">total</span>
        </div>
      </div>

      {issues.length === 0 ? (
        <div className="state-box">
          <p>No open issues found</p>
        </div>
      ) : (
        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Severity</th>
                <th>Type</th>
                <th>File</th>
                <th>Line</th>
                <th>Message</th>
                <th>Rule</th>
              </tr>
            </thead>
            <tbody>
              {issues.map((issue) => (
                <tr key={issue.key}>
                  <td>
                    <span className={`badge badge-${badgeClass(issue.severity)}`}>
                      {issue.severity}
                    </span>
                  </td>
                  <td style={{ color: 'var(--text-secondary)' }}>{issue.type || '—'}</td>
                  <td>
                    <code className="mono" style={{ fontSize: 11 }}>
                      {stripComponent(issue.component)}
                    </code>
                  </td>
                  <td style={{ color: 'var(--text-muted)' }}>{issue.line || '—'}</td>
                  <td style={{ maxWidth: 360, wordBreak: 'break-word' }}>{issue.message}</td>
                  <td>
                    <code className="mono" style={{ fontSize: 11, color: 'var(--accent)' }}>
                      {issue.rule}
                    </code>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
