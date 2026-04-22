import { useReport } from '../hooks/useReport';

function badgeClass(sev = '') {
  const l = sev.toLowerCase();
  if (l === 'critical') return 'critical';
  if (l === 'high')     return 'high';
  if (l === 'medium')   return 'medium';
  if (l === 'low')      return 'low';
  return 'info';
}

export default function TrivyReport() {
  const { data, loading, error } = useReport('trivy-report.json');

  if (loading) return <div className="state-box"><p>Loading Trivy report…</p></div>;
  if (error)   return <div className="state-box error-box"><span className="icon">⚠</span><p>{error.message}</p></div>;

  const results = data?.Results || [];

  // Flatten all vulnerabilities across all targets
  const allVulns = results.flatMap(r =>
    (r.Vulnerabilities || []).map(v => ({ ...v, _target: r.Target, _class: r.Class }))
  );

  const counts = allVulns.reduce((acc, v) => {
    const k = (v.Severity || 'unknown').toLowerCase();
    acc[k] = (acc[k] || 0) + 1;
    return acc;
  }, {});

  const sevChips = [
    ['critical', '#ef4444'],
    ['high',     '#f97316'],
    ['medium',   '#f59e0b'],
    ['low',      '#10b981'],
    ['unknown',  '#6b7280'],
  ].filter(([k]) => counts[k]);

  return (
    <div>
      <h2 className="section-title">Trivy — Container Image Scan</h2>
      <p className="section-sub">
        CVEs detected in the Docker image's OS packages and application dependencies.
        Image: <code className="mono">{data?.ArtifactName || '—'}</code>
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
          <span className="num">{allVulns.length}</span>
          <span className="lbl">total</span>
        </div>
      </div>

      {/* One table per scan target */}
      {results.length === 0 ? (
        <div className="state-box"><p>No vulnerabilities found</p></div>
      ) : (
        results.map((result, idx) => {
          const vulns = result.Vulnerabilities || [];
          if (vulns.length === 0) return null;
          return (
            <div key={idx} style={{ marginBottom: 28 }}>
              <div className="card" style={{ marginBottom: 8, padding: '10px 16px', display: 'flex', alignItems: 'center', gap: 10 }}>
                <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>Target</span>
                <code className="mono">{result.Target}</code>
                <span style={{ marginLeft: 'auto', fontSize: 12, color: 'var(--text-secondary)' }}>
                  {vulns.length} vuln{vulns.length !== 1 ? 's' : ''}
                </span>
              </div>
              <div className="table-wrapper">
                <table>
                  <thead>
                    <tr>
                      <th>CVE ID</th>
                      <th>Severity</th>
                      <th>Package</th>
                      <th>Installed</th>
                      <th>Fixed In</th>
                      <th>Title</th>
                      <th>Score</th>
                    </tr>
                  </thead>
                  <tbody>
                    {vulns.map((v, i) => {
                      const cvss = v.CVSS?.nvd?.V3Score || v.CVSS?.redhat?.V3Score || '—';
                      return (
                        <tr key={i}>
                          <td>
                            {v.PrimaryURL ? (
                              <a href={v.PrimaryURL} target="_blank" rel="noreferrer"
                                style={{ color: 'var(--accent)', fontFamily: 'var(--font-mono)', fontSize: 12 }}>
                                {v.VulnerabilityID}
                              </a>
                            ) : (
                              <code className="mono">{v.VulnerabilityID}</code>
                            )}
                          </td>
                          <td><span className={`badge badge-${badgeClass(v.Severity)}`}>{v.Severity}</span></td>
                          <td><code className="mono">{v.PkgName}</code></td>
                          <td><code className="mono" style={{ color: 'var(--text-muted)' }}>{v.InstalledVersion}</code></td>
                          <td><code className="mono" style={{ color: v.FixedVersion ? 'var(--success)' : 'var(--text-muted)' }}>{v.FixedVersion || '—'}</code></td>
                          <td style={{ maxWidth: 280, fontSize: 12, wordBreak: 'break-word' }}>{v.Title || '—'}</td>
                          <td style={{ color: typeof cvss === 'number' && cvss >= 7 ? 'var(--high)' : 'var(--text-secondary)' }}>
                            {typeof cvss === 'number' ? cvss.toFixed(1) : cvss}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          );
        })
      )}
    </div>
  );
}
