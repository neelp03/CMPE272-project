import { useReport } from '../hooks/useReport';

const RISK_MAP = {
  3: { label: 'High',          cls: 'high'     },
  2: { label: 'Medium',        cls: 'medium'   },
  1: { label: 'Low',           cls: 'low'      },
  0: { label: 'Informational', cls: 'info'     },
};

export default function ZapReport() {
  const { data, loading, error } = useReport('zap-report.json');

  if (loading) return <div className="state-box"><p>Loading OWASP ZAP report…</p></div>;
  if (error)   return <div className="state-box error-box"><span className="icon">⚠</span><p>{error.message}</p></div>;

  const sites = data?.site || [];

  // Collect all alerts across all scanned sites
  const allAlerts = sites.flatMap(s =>
    (s.alerts || []).map(a => ({
      ...a,
      _site: s['@name'] || s.name || '?',
      riskcode: parseInt(a.riskcode ?? a.riskCode ?? '0', 10),
    }))
  ).sort((a, b) => b.riskcode - a.riskcode);

  const counts = allAlerts.reduce((acc, a) => {
    const rc = a.riskcode;
    acc[rc] = (acc[rc] || 0) + 1;
    return acc;
  }, {});

  const sevChips = [3, 2, 1, 0]
    .filter(rc => counts[rc])
    .map(rc => ({ rc, color: ['#ef4444','#f97316','#f59e0b','#6b7280'][3 - rc] }));

  return (
    <div>
      <h2 className="section-title">OWASP ZAP — Dynamic Analysis (DAST)</h2>
      <p className="section-sub">
        Runtime vulnerabilities discovered by actively scanning the running API.
        Generated: <span style={{ color: 'var(--text-secondary)' }}>{data?.['@generated'] || '—'}</span>
      </p>

      <div className="sev-row">
        {sevChips.map(({ rc, color }) => (
          <div className="sev-chip" key={rc}>
            <span className="dot" style={{ background: color }} />
            <span className="num">{counts[rc]}</span>
            <span className="lbl">{RISK_MAP[rc]?.label}</span>
          </div>
        ))}
        <div className="sev-chip">
          <span className="num">{allAlerts.length}</span>
          <span className="lbl">total</span>
        </div>
      </div>

      {allAlerts.length === 0 ? (
        <div className="state-box">
          <span className="icon">✅</span>
          <p>No alerts found</p>
        </div>
      ) : (
        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Risk</th>
                <th>Alert</th>
                <th>Instances</th>
                <th>CWE</th>
                <th>WASC</th>
                <th>Solution (brief)</th>
              </tr>
            </thead>
            <tbody>
              {allAlerts.map((alert, idx) => {
                const risk = RISK_MAP[alert.riskcode] || RISK_MAP[0];
                const instances = alert.instances || [];
                const count = parseInt(alert.count || instances.length, 10);
                // strip HTML tags from desc/solution for display
                const stripHtml = (s = '') => s.replace(/<[^>]+>/g, '').trim().slice(0, 160);

                return (
                  <tr key={idx}>
                    <td>
                      <span className={`badge badge-${risk.cls}`}>{risk.label}</span>
                    </td>
                    <td style={{ fontWeight: 500 }}>{alert.alert || alert.name}</td>
                    <td style={{ color: 'var(--text-muted)' }}>{count}</td>
                    <td>
                      {alert.cweid && alert.cweid !== '0' ? (
                        <a href={`https://cwe.mitre.org/data/definitions/${alert.cweid}.html`}
                          target="_blank" rel="noreferrer"
                          style={{ color: 'var(--accent)', fontSize: 12 }}>
                          CWE-{alert.cweid}
                        </a>
                      ) : '—'}
                    </td>
                    <td style={{ color: 'var(--text-muted)', fontSize: 12 }}>
                      {alert.wascid && alert.wascid !== '0' ? `WASC-${alert.wascid}` : '—'}
                    </td>
                    <td style={{ fontSize: 12, color: 'var(--text-secondary)', maxWidth: 280, wordBreak: 'break-word' }}>
                      {stripHtml(alert.solution)}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Instance detail for high/medium findings */}
      {allAlerts.filter(a => a.riskcode >= 2).map((alert, idx) => {
        const instances = alert.instances || [];
        if (!instances.length) return null;
        return (
          <div key={idx} className="card" style={{ marginTop: 16 }}>
            <p className="card-title">
              {alert.alert || alert.name} — Affected URLs ({instances.length})
            </p>
            <div className="table-wrapper" style={{ marginTop: 0 }}>
              <table>
                <thead>
                  <tr><th>Method</th><th>URL</th><th>Parameter</th><th>Evidence</th></tr>
                </thead>
                <tbody>
                  {instances.slice(0, 10).map((inst, i) => (
                    <tr key={i}>
                      <td><span className="badge badge-info">{inst.method || 'GET'}</span></td>
                      <td><code className="mono" style={{ fontSize: 11 }}>{inst.uri}</code></td>
                      <td style={{ color: 'var(--text-muted)' }}>{inst.param || '—'}</td>
                      <td style={{ color: 'var(--text-muted)', fontSize: 12 }}>{inst.evidence || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        );
      })}
    </div>
  );
}
