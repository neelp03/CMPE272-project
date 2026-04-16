import { useState } from 'react';
import { useReport } from './hooks/useReport';
import Overview       from './components/Overview';
import NpmAuditReport from './components/NpmAuditReport';
import SonarReport    from './components/SonarReport';
import TrivyReport    from './components/TrivyReport';
import ZapReport      from './components/ZapReport';

const NAV = [
  { id: 'overview', label: 'Command Center',   icon: '▦' },
  { id: 'npm',      label: 'Dependency Scan',  icon: '📦' },
  { id: 'sonar',    label: 'Static Analysis',  icon: '🔍' },
  { id: 'trivy',    label: 'Infrastructure',   icon: '🐳' },
  { id: 'zap',      label: 'Live Probe',        icon: '⚡' },
];

const JOB_LABELS = {
  dependencyScan: 'npm audit',
  sast:           'SonarCloud',
  trivyScan:      'Trivy',
  dast:           'OWASP ZAP',
};

export default function App() {
  const [active, setActive] = useState('overview');
  const meta = useReport('pipeline-meta.json');
  const status = meta.data?.jobStatus || {};

  const statusColor = (s) =>
    s === 'success' ? 'var(--low)'      :
    s === 'failure' ? 'var(--critical)' :
    s === 'skipped' ? 'var(--info)'     : 'var(--text-muted)';

  const statusDot = (s) =>
    s === 'success' ? 'var(--low)'      :
    s === 'failure' ? 'var(--critical)' :
    s === 'skipped' ? 'var(--info)'     : '#cbd5e1';

  return (
    <div className="layout">
      {/* scan-line decoration */}
      <div className="scan-line" />

      {/* ── Sidebar ───────────────────────────────────────── */}
      <aside className="sidebar">
        <div className="sidebar-brand">
          <div className="brand-icon">🛡</div>
          <span className="brand-text">Dev<span>SecOps</span></span>
        </div>

        <nav className="sidebar-nav">
          {NAV.map(({ id, label, icon }) => (
            <button
              key={id}
              className={`nav-item ${active === id ? 'active' : ''}`}
              onClick={() => setActive(id)}
            >
              <span className="nav-icon">{icon}</span>
              <span>{label}</span>
            </button>
          ))}
        </nav>

        {/* Pipeline job status */}
        {meta.data && (
          <div className="sidebar-status">
            <p className="sidebar-status-title">Pipeline Status</p>
            {Object.entries(status).map(([job, result]) => (
              <div key={job} className="status-row">
                <span className="status-job">{JOB_LABELS[job] || job}</span>
                <span className="status-badge" style={{ color: statusColor(result) }}>
                  {result}
                </span>
              </div>
            ))}
          </div>
        )}
      </aside>

      {/* ── Main content ─────────────────────────────────── */}
      <div className="main">
        {/* Top bar */}
        <header className="topbar">
          <div className="topbar-left">
            <div className="topbar-title-row">
              <h1 className="topbar-title">Security Intelligence</h1>
              <span className="topbar-live-badge">Live Threat Matrix</span>
            </div>
            {meta.data && (
              <p className="topbar-meta">
                Branch:&nbsp;<code>{meta.data.branch}</code>
                &nbsp;·&nbsp;Commit:&nbsp;<code>{meta.data.commit?.slice(0, 7)}</code>
                &nbsp;·&nbsp;Run&nbsp;<code>#{meta.data.runNumber}</code>
              </p>
            )}
          </div>

          {meta.data && (
            <div className="topbar-run-info">
              <span className="topbar-run-label">Last Scanned</span>
              <span className="topbar-run-value">
                {new Date(meta.data.timestamp).toLocaleString()}
              </span>
            </div>
          )}
        </header>

        {/* Content pane */}
        <main className="content">
          {active === 'overview' && <Overview />}
          {active === 'npm'      && <NpmAuditReport />}
          {active === 'sonar'    && <SonarReport />}
          {active === 'trivy'    && <TrivyReport />}
          {active === 'zap'      && <ZapReport />}
        </main>
      </div>
    </div>
  );
}
