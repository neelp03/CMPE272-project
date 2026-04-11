import { useReport } from '../hooks/useReport';
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Legend,
} from 'recharts';

const SEV_COLORS = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#f59e0b',
  low:      '#10b981',
  info:     '#6b7280',
};

/* ── helpers ────────────────────────────────────────────────── */

function npmCounts(data) {
  if (!data?.metadata?.vulnerabilities) return null;
  const v = data.metadata.vulnerabilities;
  return {
    critical: v.critical || 0,
    high:     v.high     || 0,
    medium:   v.moderate || 0,
    low:      v.low      || 0,
    total:    v.total    || 0,
  };
}

function sonarCounts(data) {
  if (!data?.issues) return null;
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  data.issues.forEach(i => {
    const s = (i.severity || '').toLowerCase();
    if (s === 'blocker' || s === 'critical') counts.critical++;
    else if (s === 'major')                  counts.high++;
    else if (s === 'minor')                  counts.medium++;
    else                                      counts.low++;
  });
  counts.total = data.total || data.issues.length;
  return counts;
}

function trivyCounts(data) {
  if (!data?.Results) return null;
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  data.Results.forEach(r =>
    (r.Vulnerabilities || []).forEach(v => {
      const s = (v.Severity || '').toLowerCase();
      if (counts[s] !== undefined) counts[s]++;
    })
  );
  counts.total = Object.values(counts).reduce((a, b) => a + b, 0);
  return counts;
}

function zapCounts(data) {
  if (!data?.site) return null;
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  data.site.forEach(s =>
    (s.alerts || []).forEach(a => {
      const rc = parseInt(a.riskcode || '0', 10);
      if (rc >= 3)      counts.critical++;
      else if (rc === 2) counts.high++;
      else if (rc === 1) counts.medium++;
      else               counts.info++;
    })
  );
  counts.total = Object.values(counts).reduce((a, b) => a + b, 0);
  return counts;
}

/* ── sub-components ─────────────────────────────────────────── */

function ToolCard({ icon, name, counts, loading, error }) {
  if (loading) return (
    <div className="tool-card">
      <div className="state-box" style={{ minHeight: 120 }}>
        <p>Loading…</p>
      </div>
    </div>
  );

  if (error || !counts) return (
    <div className="tool-card">
      <div className="tool-card-header">
        <span className="tool-card-name">{icon} {name}</span>
      </div>
      <p style={{ color: 'var(--text-muted)', fontSize: 12 }}>
        {error ? 'Report not available' : 'No data'}
      </p>
    </div>
  );

  return (
    <div className="tool-card">
      <div className="tool-card-header">
        <span className="tool-card-name">{icon} {name}</span>
        <span className="tool-total" style={{
          color: counts.critical > 0 ? SEV_COLORS.critical :
                 counts.high     > 0 ? SEV_COLORS.high     : 'var(--success)',
        }}>
          {counts.total}
        </span>
      </div>
      <div className="tool-sev-row">
        {[['critical','C'],['high','H'],['medium','M'],['low','L']].map(([k, l]) =>
          counts[k] > 0 && (
            <span key={k} className={`badge badge-${k}`}>{l}: {counts[k]}</span>
          )
        )}
        {counts.total === 0 && <span style={{ color: 'var(--success)', fontSize:13 }}>✓ Clean</span>}
      </div>
    </div>
  );
}

function SeverityPie({ label, counts }) {
  if (!counts) return null;
  const pieData = Object.entries(SEV_COLORS)
    .map(([k, color]) => ({ name: k, value: counts[k] || 0, color }))
    .filter(d => d.value > 0);

  if (!pieData.length) return (
    <div className="card">
      <p className="card-title">{label}</p>
      <div className="state-box" style={{ minHeight: 180 }}>
        <span className="icon">✅</span>
        <p>No findings</p>
      </div>
    </div>
  );

  return (
    <div className="card">
      <p className="card-title">{label}</p>
      <ResponsiveContainer width="100%" height={200}>
        <PieChart>
          <Pie data={pieData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={75} label={({ name, value }) => `${name}: ${value}`}>
            {pieData.map((d, i) => <Cell key={i} fill={d.color} />)}
          </Pie>
          <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 6 }} />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}

/* ── main component ─────────────────────────────────────────── */

export default function Overview() {
  const npm   = useReport('npm-audit.json');
  const sonar = useReport('sonar-issues.json');
  const trivy = useReport('trivy-report.json');
  const zap   = useReport('zap-report.json');

  const nc = npmCounts(npm.data);
  const sc = sonarCounts(sonar.data);
  const tc = trivyCounts(trivy.data);
  const zc = zapCounts(zap.data);

  // Aggregated bar chart data
  const barData = [
    { tool: 'npm audit',  ...nc },
    { tool: 'SonarCloud', ...sc },
    { tool: 'Trivy',      ...tc },
    { tool: 'OWASP ZAP',  ...zc },
  ].filter(d => d.total !== undefined);

  const grandTotal = [nc, sc, tc, zc]
    .filter(Boolean)
    .reduce((sum, c) => sum + (c.total || 0), 0);

  return (
    <div>
      <h2 className="section-title">Security Overview</h2>
      <p className="section-sub">Aggregated findings across all pipeline scan tools.</p>

      {/* Grand total */}
      <div className="stat-grid" style={{ marginBottom: 24 }}>
        <div className="stat-card">
          <span className="stat-label">Total Findings</span>
          <span className="stat-value" style={{ color: grandTotal > 0 ? 'var(--critical)' : 'var(--success)' }}>
            {grandTotal}
          </span>
          <span className="stat-sub">across all tools</span>
        </div>
        {nc && <div className="stat-card">
          <span className="stat-label">npm audit</span>
          <span className="stat-value" style={{ color: nc.critical > 0 ? 'var(--critical)' : nc.high > 0 ? 'var(--high)' : 'var(--success)' }}>{nc.total}</span>
          <span className="stat-sub">dependency vulns</span>
        </div>}
        {sc && <div className="stat-card">
          <span className="stat-label">SonarCloud</span>
          <span className="stat-value" style={{ color: sc.critical > 0 ? 'var(--critical)' : sc.high > 0 ? 'var(--high)' : 'var(--success)' }}>{sc.total}</span>
          <span className="stat-sub">SAST issues</span>
        </div>}
        {tc && <div className="stat-card">
          <span className="stat-label">Trivy</span>
          <span className="stat-value" style={{ color: tc.critical > 0 ? 'var(--critical)' : tc.high > 0 ? 'var(--high)' : 'var(--success)' }}>{tc.total}</span>
          <span className="stat-sub">container CVEs</span>
        </div>}
        {zc && <div className="stat-card">
          <span className="stat-label">OWASP ZAP</span>
          <span className="stat-value" style={{ color: zc.critical > 0 ? 'var(--critical)' : zc.high > 0 ? 'var(--high)' : 'var(--success)' }}>{zc.total}</span>
          <span className="stat-sub">DAST findings</span>
        </div>}
      </div>

      {/* Per-tool cards */}
      <div className="tool-grid">
        <ToolCard icon="📦" name="npm audit"   counts={nc} loading={npm.loading}   error={npm.error} />
        <ToolCard icon="🔍" name="SonarCloud"  counts={sc} loading={sonar.loading} error={sonar.error} />
        <ToolCard icon="🐳" name="Trivy"        counts={tc} loading={trivy.loading} error={trivy.error} />
        <ToolCard icon="⚡" name="OWASP ZAP"   counts={zc} loading={zap.loading}   error={zap.error} />
      </div>

      {/* Charts */}
      {barData.length > 0 && (
        <div className="chart-grid">
          <div className="card">
            <p className="card-title">Findings by Tool &amp; Severity</p>
            <ResponsiveContainer width="100%" height={240}>
              <BarChart data={barData} margin={{ top: 5, right: 10, left: -10, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis dataKey="tool" tick={{ fill: '#94a3b8', fontSize: 12 }} />
                <YAxis tick={{ fill: '#94a3b8', fontSize: 12 }} allowDecimals={false} />
                <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 6 }} />
                <Legend wrapperStyle={{ fontSize: 12 }} />
                <Bar dataKey="critical" fill={SEV_COLORS.critical} stackId="a" />
                <Bar dataKey="high"     fill={SEV_COLORS.high}     stackId="a" />
                <Bar dataKey="medium"   fill={SEV_COLORS.medium}   stackId="a" />
                <Bar dataKey="low"      fill={SEV_COLORS.low}      stackId="a" radius={[4,4,0,0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>

          <SeverityPie label="SonarCloud Severity Mix" counts={sc} />
          <SeverityPie label="Trivy Severity Mix"      counts={tc} />
        </div>
      )}
    </div>
  );
}
