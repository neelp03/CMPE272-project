import { useReport } from '../hooks/useReport';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer,
} from 'recharts';

const SEV_COLORS = {
  critical: '#f43f5e',
  high:     '#f97316',
  medium:   '#f59e0b',
  low:      '#10b981',
};

/* ── Helpers ─────────────────────────────────────────────────── */

function npmCounts(data) {
  if (!data?.metadata?.vulnerabilities) return null;
  const v = data.metadata.vulnerabilities;
  return { critical: v.critical||0, high: v.high||0, medium: v.moderate||0, low: v.low||0 };
}

function sonarCounts(data) {
  if (!data?.issues) return null;
  const c = { critical:0, high:0, medium:0, low:0 };
  data.issues.forEach(i => {
    const s = (i.severity||'').toLowerCase();
    if (s==='blocker'||s==='critical') c.critical++;
    else if (s==='major')              c.high++;
    else if (s==='minor')              c.medium++;
    else                               c.low++;
  });
  return c;
}

function trivyCounts(data) {
  if (!data?.Results) return null;
  const c = { critical:0, high:0, medium:0, low:0 };
  data.Results.forEach(r =>
    (r.Vulnerabilities||[]).forEach(v => {
      const s = (v.Severity||'').toLowerCase();
      if (c[s]!==undefined) c[s]++;
    })
  );
  return c;
}

function zapCounts(data) {
  if (!data?.site) return null;
  const c = { critical:0, high:0, medium:0, low:0 };
  data.site.forEach(s =>
    (s.alerts||[]).forEach(a => {
      const rc = parseInt(a.riskcode||'0',10);
      if (rc>=3)       c.critical++;
      else if (rc===2) c.high++;
      else if (rc===1) c.medium++;
      else             c.low++;
    })
  );
  return c;
}

function total(c) {
  if (!c) return 0;
  return (c.critical||0)+(c.high||0)+(c.medium||0)+(c.low||0);
}

/* Extract top findings from each tool for the threat panel */
function topThreats(npmData, sonarData, trivyData, zapData) {
  const findings = [];

  // npm audit
  Object.entries(npmData?.vulnerabilities||{}).forEach(([name, v]) => {
    const via = Array.isArray(v.via) ? v.via.filter(x=>typeof x==='object') : [];
    findings.push({
      tool: 'npm audit',
      severity: v.severity||'low',
      title: name,
      location: v.range||'',
      _order: {critical:0,high:1,moderate:2,medium:2,low:3}[v.severity]??4,
    });
  });

  // SonarCloud
  (sonarData?.issues||[]).forEach(issue => {
    const s = (issue.severity||'').toLowerCase();
    const sev = s==='blocker'||s==='critical'?'critical':s==='major'?'high':s==='minor'?'medium':'low';
    const loc = issue.component?.includes(':') ? issue.component.split(':').slice(1).join(':') : (issue.component||'');
    findings.push({
      tool: 'SonarCloud',
      severity: sev,
      title: issue.message||issue.rule||'Issue',
      location: loc + (issue.line ? `:${issue.line}` : ''),
      _order: {critical:0,high:1,medium:2,low:3}[sev]??4,
    });
  });

  // Trivy
  (trivyData?.Results||[]).forEach(r =>
    (r.Vulnerabilities||[]).forEach(v => {
      const sev = (v.Severity||'low').toLowerCase();
      findings.push({
        tool: 'Trivy',
        severity: sev,
        title: v.VulnerabilityID||(v.Title||'CVE'),
        location: `${v.PkgName}@${v.InstalledVersion}`,
        _order: {critical:0,high:1,medium:2,low:3}[sev]??4,
      });
    })
  );

  // ZAP
  const RISK_SEV = {3:'critical',2:'high',1:'medium',0:'low'};
  (zapData?.site||[]).forEach(s =>
    (s.alerts||[]).forEach(a => {
      const rc = parseInt(a.riskcode||'0',10);
      const sev = RISK_SEV[rc]||'low';
      findings.push({
        tool: 'OWASP ZAP',
        severity: sev,
        title: a.name||a.alert||'Alert',
        location: a.instances?.[0]?.uri||s['@name']||'',
        _order: rc>=3?0:rc===2?1:rc===1?2:3,
      });
    })
  );

  return findings.sort((a,b)=>a._order-b._order).slice(0,12);
}

/* ── Custom Tooltip ──────────────────────────────────────────── */
function CustomTooltip({ active, payload, label }) {
  if (!active||!payload?.length) return null;
  return (
    <div style={{ background:'#fff', border:'1px solid #e2e8f0', borderRadius:8, padding:'10px 14px', boxShadow:'0 4px 12px rgba(0,0,0,0.08)', fontSize:12 }}>
      <p style={{ fontWeight:700, marginBottom:6, color:'#1e293b' }}>{label}</p>
      {payload.map(p => (
        <div key={p.dataKey} style={{ display:'flex', justifyContent:'space-between', gap:16, color: p.fill, fontWeight:600 }}>
          <span style={{ textTransform:'capitalize' }}>{p.dataKey}</span>
          <span>{p.value}</span>
        </div>
      ))}
    </div>
  );
}

/* ── Main component ──────────────────────────────────────────── */
export default function Overview() {
  const npm   = useReport('npm-audit.json');
  const sonar = useReport('sonar-issues.json');
  const trivy = useReport('trivy-report.json');
  const zap   = useReport('zap-report.json');
  const meta  = useReport('pipeline-meta.json');

  const nc = npmCounts(npm.data);
  const sc = sonarCounts(sonar.data);
  const tc = trivyCounts(trivy.data);
  const zc = zapCounts(zap.data);

  const allCounts = [nc, sc, tc, zc].filter(Boolean);
  const totalFindings = allCounts.reduce((s,c)=>s+total(c), 0);
  const totalCritical = allCounts.reduce((s,c)=>s+(c.critical||0), 0);
  const totalHigh     = allCounts.reduce((s,c)=>s+(c.high||0), 0);
  const totalMedium   = allCounts.reduce((s,c)=>s+(c.medium||0), 0);
  const totalLow      = allCounts.reduce((s,c)=>s+(c.low||0), 0);
  const passed        = totalCritical === 0;

  const jobStatus = meta.data?.jobStatus || {};
  const pipelineStages = [
    { key:'dependencyScan', label:'npm audit' },
    { key:'sast',           label:'SonarCloud' },
    { key:'trivyScan',      label:'Trivy' },
    { key:'dast',           label:'OWASP ZAP' },
  ];

  const stageColor = (s) =>
    s==='success' ? '#10b981' : s==='failure' ? '#f43f5e' : s==='skipped' ? '#94a3b8' : '#f59e0b';

  const barData = [
    { tool:'npm audit',  ...nc },
    { tool:'SonarCloud', ...sc },
    { tool:'Trivy',      ...tc },
    { tool:'OWASP ZAP',  ...zc },
  ].filter(d => d.tool && (d.critical!==undefined||d.high!==undefined));

  const threats = topThreats(npm.data||{}, sonar.data||{}, trivy.data||{}, zap.data||{});

  const severityLabel = (s) => ({ critical:'Critical', high:'High', medium:'Medium', low:'Low' }[s]||s);

  return (
    <div>
      <h2 className="section-title">Command Center</h2>
      <p className="section-sub">Aggregated security findings across all pipeline scan tools.</p>

      {/* Pipeline stage pills */}
      {meta.data && (
        <div className="pipeline-strip">
          {pipelineStages.map(({ key, label }) => {
            const result = jobStatus[key];
            if (!result) return null;
            return (
              <div key={key} className="pipeline-stage">
                <span className="pipeline-dot" style={{ background: stageColor(result) }} />
                <span style={{ color: '#475569', fontSize: 12 }}>{label}</span>
                <span style={{ color: stageColor(result), fontFamily:'var(--font-mono)', fontSize:10, fontWeight:700, textTransform:'uppercase' }}>
                  {result}
                </span>
              </div>
            );
          })}
          <div className="pipeline-stage" style={{ marginLeft:'auto', borderColor: passed ? '#bbf7d0' : '#fecdd3', background: passed ? '#f0fdf4' : '#fff1f2' }}>
            <span className="pipeline-dot" style={{ background: passed ? '#10b981' : '#f43f5e' }} />
            <span style={{ color: passed ? '#10b981' : '#f43f5e', fontWeight:700, fontSize:12 }}>
              {passed ? 'Deploy Unblocked' : 'Deploy Blocked'}
            </span>
          </div>
        </div>
      )}

      {/* Stat cards */}
      <div className="stat-grid">
        <div className="stat-card">
          <span className="stat-card-icon">🔎</span>
          <span className="stat-label">Total Findings</span>
          <span className="stat-value" style={{ color: totalFindings>0 ? 'var(--critical)' : 'var(--low)' }}>
            {totalFindings}
          </span>
          <span className="stat-sub">across all tools</span>
        </div>
        <div className="stat-card">
          <span className="stat-card-icon">🔥</span>
          <span className="stat-label">Critical Risks</span>
          <span className="stat-value" style={{ color:'var(--critical)' }}>{totalCritical}</span>
          <span className="stat-sub" style={{ color: totalCritical>0 ? 'var(--critical)' : 'var(--low)' }}>
            {totalCritical>0 ? 'Immediate action required' : 'No critical issues'}
          </span>
          {totalFindings>0 && (
            <div className="stat-bar">
              <div className="stat-bar-fill" style={{ width:`${Math.min(100,(totalCritical/totalFindings)*100)}%`, background:'var(--critical)' }} />
            </div>
          )}
        </div>
        <div className="stat-card">
          <span className="stat-card-icon">⚠️</span>
          <span className="stat-label">High Alerts</span>
          <span className="stat-value" style={{ color:'var(--high)' }}>{totalHigh}</span>
          <span className="stat-sub">need review</span>
          {totalFindings>0 && (
            <div className="stat-bar">
              <div className="stat-bar-fill" style={{ width:`${Math.min(100,(totalHigh/totalFindings)*100)}%`, background:'var(--high)' }} />
            </div>
          )}
        </div>
        <div className="stat-card">
          <span className="stat-card-icon">📋</span>
          <span className="stat-label">Medium Issues</span>
          <span className="stat-value" style={{ color:'var(--medium)' }}>{totalMedium}</span>
          <span className="stat-sub">monitor closely</span>
        </div>
        <div className="stat-card">
          <span className="stat-card-icon">✅</span>
          <span className="stat-label">Low / Info</span>
          <span className="stat-value" style={{ color:'var(--low)' }}>{totalLow}</span>
          <span className="stat-sub">informational</span>
        </div>
      </div>

      {/* Tool summary cards */}
      <div className="tool-grid">
        {[
          { icon:'📦', name:'npm audit',  counts:nc, loading:npm.loading,   error:npm.error   },
          { icon:'🔍', name:'SonarCloud', counts:sc, loading:sonar.loading, error:sonar.error },
          { icon:'🐳', name:'Trivy',       counts:tc, loading:trivy.loading, error:trivy.error },
          { icon:'⚡', name:'OWASP ZAP',  counts:zc, loading:zap.loading,   error:zap.error   },
        ].map(({ icon, name, counts, loading, error }) => {
          if (loading) return (
            <div key={name} className="tool-card">
              <p style={{ color:'var(--text-muted)', fontSize:12 }}>Loading…</p>
            </div>
          );
          const t = total(counts);
          const hasError = error || !counts;
          return (
            <div key={name} className="tool-card">
              <div className="tool-card-header">
                <span className="tool-card-name">{icon} {name}</span>
                <span className="tool-total" style={{
                  color: hasError ? 'var(--text-muted)' :
                         counts.critical>0 ? 'var(--critical)' :
                         counts.high>0     ? 'var(--high)'     : 'var(--low)',
                }}>
                  {hasError ? '—' : t}
                </span>
              </div>
              {hasError ? (
                <p style={{ color:'var(--text-muted)', fontSize:12 }}>Report not available</p>
              ) : (
                <div className="tool-sev-row">
                  {counts.critical>0 && <span className="badge badge-critical">C: {counts.critical}</span>}
                  {counts.high>0     && <span className="badge badge-high">H: {counts.high}</span>}
                  {counts.medium>0   && <span className="badge badge-medium">M: {counts.medium}</span>}
                  {counts.low>0      && <span className="badge badge-low">L: {counts.low}</span>}
                  {t===0 && <span style={{ color:'var(--low)', fontSize:12, fontWeight:600 }}>✓ Clean</span>}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* 2-column: chart + top threats */}
      <div className="overview-body">
        {/* Chart */}
        <div className="overview-main">
          {barData.length > 0 && (
            <div className="chart-card" style={{ marginBottom:0 }}>
              <p className="chart-title">Findings by Tool &amp; Severity</p>
              <ResponsiveContainer width="100%" height={260}>
                <BarChart data={barData} margin={{ top:5, right:10, left:-10, bottom:5 }} barSize={14}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" vertical={false} />
                  <XAxis dataKey="tool" tick={{ fill:'#94a3b8', fontSize:12, fontWeight:600 }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fill:'#94a3b8', fontSize:11 }} axisLine={false} tickLine={false} allowDecimals={false} />
                  <Tooltip content={<CustomTooltip />} cursor={{ fill:'rgba(0,0,0,0.03)' }} />
                  <Legend wrapperStyle={{ fontSize:12, paddingTop:12 }} iconType="circle" />
                  <Bar dataKey="critical" name="Critical" fill={SEV_COLORS.critical} radius={[4,4,0,0]} />
                  <Bar dataKey="high"     name="High"     fill={SEV_COLORS.high}     radius={[4,4,0,0]} />
                  <Bar dataKey="medium"   name="Medium"   fill={SEV_COLORS.medium}   radius={[4,4,0,0]} />
                  <Bar dataKey="low"      name="Low"      fill={SEV_COLORS.low}       radius={[4,4,0,0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>

        {/* Top threats */}
        <div className="overview-side">
          <div className="threats-panel">
            <div className="threats-header">Top Threats</div>
            <div className="threats-list">
              {threats.length === 0 ? (
                <div className="state-box" style={{ minHeight:120 }}>
                  <span style={{ fontSize:28 }}>✅</span>
                  <p style={{ fontSize:13 }}>No findings</p>
                </div>
              ) : threats.map((t, i) => (
                <div key={i} className="threat-item">
                  <div className="threat-item-top">
                    <span className="threat-item-title">{t.title}</span>
                    <span className={`badge badge-${t.severity}`}>{severityLabel(t.severity)}</span>
                  </div>
                  <div style={{ display:'flex', alignItems:'center', gap:8 }}>
                    <span className="threat-tool-tag">{t.tool}</span>
                    <span className="threat-item-meta">{t.location}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
