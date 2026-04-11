import { useState } from 'react';
import { useReport } from './hooks/useReport';
import Overview       from './components/Overview';
import NpmAuditReport from './components/NpmAuditReport';
import SonarReport    from './components/SonarReport';
import TrivyReport    from './components/TrivyReport';
import ZapReport      from './components/ZapReport';

const NAV = [
  { id: 'overview', label: 'Overview',       icon: '▦' },
  { id: 'npm',      label: 'npm audit',       icon: '📦' },
  { id: 'sonar',    label: 'SonarCloud',      icon: '🔍' },
  { id: 'trivy',    label: 'Trivy',           icon: '🐳' },
  { id: 'zap',      label: 'OWASP ZAP',       icon: '⚡' },
];

export default function App() {
  const [active, setActive] = useState('overview');
  const meta = useReport('pipeline-meta.json');

  const status = meta.data?.jobStatus || {};
  const statusColor = (s) =>
    s === 'success' ? 'var(--success)' :
    s === 'failure' ? 'var(--critical)' :
    s === 'skipped' ? 'var(--info)' : 'var(--text-secondary)';

  return (
    <div className="layout">
      {/* ── Sidebar ─────────────────────────────────────── */}
      <aside className="sidebar">
        <div className="sidebar-brand">
          <span className="brand-icon">🛡</span>
          <span className="brand-text">DevSecOps</span>
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

        {/* Pipeline job status badges */}
        {meta.data && (
          <div className="sidebar-status">
            <p className="sidebar-status-title">Pipeline Jobs</p>
            {Object.entries(status).map(([job, result]) => (
              <div key={job} className="status-row">
                <span className="status-job">{job}</span>
                <span className="status-badge" style={{ color: statusColor(result) }}>
                  {result}
                </span>
              </div>
            ))}
          </div>
        )}
      </aside>

      {/* ── Main content ────────────────────────────────── */}
      <div className="main">
        {/* Top bar */}
        <header className="topbar">
          <div>
            <h1 className="topbar-title">Security Dashboard</h1>
            {meta.data && (
              <p className="topbar-meta">
                Run&nbsp;<strong>#{meta.data.runNumber}</strong>
                &nbsp;·&nbsp;
                <code>{meta.data.commit?.slice(0, 7)}</code>
                &nbsp;·&nbsp;
                {meta.data.branch}
                &nbsp;·&nbsp;
                {new Date(meta.data.timestamp).toLocaleString()}
              </p>
            )}
          </div>
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
