import { useReport } from '../hooks/useReport';

function severityClass(s = '') {
  const l = s.toLowerCase();
  if (l === 'critical')              return 'critical';
  if (l === 'high')                  return 'high';
  if (l === 'moderate' || l === 'medium') return 'medium';
  if (l === 'low')                   return 'low';
  return 'info';
}

export default function NpmAuditReport() {
  const { data, loading, error } = useReport('npm-audit.json');

  if (loading) return <div className="state-box"><p>Loading npm audit report…</p></div>;
  if (error)   return <div className="state-box error-box"><span className="icon">⚠</span><p>{error.message}</p></div>;

  const meta   = data?.metadata?.vulnerabilities || {};
  const vulns  = Object.values(data?.vulnerabilities || {});

  const total    = meta.total    || vulns.length;
  const critical = meta.critical || 0;
  const high     = meta.high     || 0;
  const moderate = meta.moderate || 0;
  const low      = (meta.low || 0) + (meta.info || 0);

  return (
    <div>
      <h2 className="section-title">npm audit — Dependency Vulnerabilities</h2>
      <p className="section-sub">
        Scans installed packages against the npm advisory database.
      </p>

      {/* Summary chips */}
      <div className="sev-row">
        {[
          ['critical', critical, '#ef4444'],
          ['high',     high,     '#f97316'],
          ['moderate', moderate, '#f59e0b'],
          ['low',      low,      '#10b981'],
        ].map(([label, n, color]) => (
          <div className="sev-chip" key={label}>
            <span className="dot" style={{ background: color }} />
            <span className="num">{n}</span>
            <span className="lbl">{label}</span>
          </div>
        ))}
        <div className="sev-chip">
          <span className="num">{total}</span>
          <span className="lbl">total</span>
        </div>
      </div>

      {/* Vulnerability table */}
      {vulns.length === 0 ? (
        <div className="state-box">
          <span className="icon">✅</span>
          <p>No vulnerabilities found</p>
        </div>
      ) : (
        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Package</th>
                <th>Severity</th>
                <th>Affected Range</th>
                <th>Fix Available</th>
                <th>Advisory</th>
              </tr>
            </thead>
            <tbody>
              {vulns.map((v) => {
                const via = Array.isArray(v.via) ? v.via.filter(x => typeof x === 'object') : [];
                const advisory = via[0] || {};
                const sev = severityClass(v.severity);
                const fixInfo = v.fixAvailable;
                const fixText = !fixInfo
                  ? '—'
                  : typeof fixInfo === 'boolean'
                    ? 'Yes'
                    : `${fixInfo.name}@${fixInfo.version}`;

                return (
                  <tr key={v.name}>
                    <td><code className="mono">{v.name}</code></td>
                    <td><span className={`badge badge-${sev}`}>{v.severity}</span></td>
                    <td><code className="mono">{v.range || advisory.range || '—'}</code></td>
                    <td style={{ color: fixInfo ? 'var(--success)' : 'var(--text-muted)' }}>{fixText}</td>
                    <td>
                      {advisory.url ? (
                        <a href={advisory.url} target="_blank" rel="noreferrer"
                          style={{ color: 'var(--accent)', fontSize: 12 }}>
                          {advisory.title || 'View'}
                        </a>
                      ) : <span>{advisory.title || '—'}</span>}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Raw metadata */}
      <div className="card" style={{ marginTop: 20 }}>
        <p className="card-title">Dependency Counts</p>
        <div className="stat-grid" style={{ marginBottom: 0 }}>
          {Object.entries(data?.metadata?.dependencies || {}).map(([k, v]) => (
            <div key={k} style={{ padding: '8px 0' }}>
              <span style={{ color: 'var(--text-secondary)', fontSize: 12 }}>{k}: </span>
              <strong>{v}</strong>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
