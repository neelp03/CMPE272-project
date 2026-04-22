import { useState } from 'react';
import { useReport } from './hooks/useReport';
import Overview       from './components/Overview';
import NpmAuditReport from './components/NpmAuditReport';
import SonarReport    from './components/SonarReport';
import TrivyReport    from './components/TrivyReport';
import ZapReport      from './components/ZapReport';

/* ── SVG icons (stroke-based, inherit currentColor) ─────────── */
const IconShield = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none"
    stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
  </svg>
);

const IconGrid = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none"
    stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="3" y="3" width="7" height="7" rx="1"/>
    <rect x="14" y="3" width="7" height="7" rx="1"/>
    <rect x="14" y="14" width="7" height="7" rx="1"/>
    <rect x="3" y="14" width="7" height="7" rx="1"/>
  </svg>
);

const IconPackage = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none"
    stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/>
    <polyline points="3.27 6.96 12 12.01 20.73 6.96"/>
    <line x1="12" y1="22.08" x2="12" y2="12"/>
  </svg>
);

const IconCode = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none"
    stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="16 18 22 12 16 6"/>
    <polyline points="8 6 2 12 8 18"/>
  </svg>
);

const IconLayers = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none"
    stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polygon points="12 2 2 7 12 12 22 7 12 2"/>
    <polyline points="2 17 12 22 22 17"/>
    <polyline points="2 12 12 17 22 12"/>
  </svg>
);

const IconZap = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none"
    stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>
  </svg>
);

/* ── Nav items ───────────────────────────────────────────────── */
const NAV = [
  { id: 'overview', label: 'Command Center',  Icon: IconGrid    },
  { id: 'npm',      label: 'Dependency Scan', Icon: IconPackage },
  { id: 'sonar',    label: 'Static Analysis', Icon: IconCode    },
  { id: 'trivy',    label: 'Infrastructure',  Icon: IconLayers  },
  { id: 'zap',      label: 'Live Probe',       Icon: IconZap     },
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

  return (
    <div className="layout">

      {/* ── Sidebar ───────────────────────────────────────── */}
      <aside className="sidebar">
        <div className="sidebar-brand">
          <div className="brand-icon"><IconShield /></div>
          <span className="brand-text">Dev<span>SecOps</span></span>
        </div>

        <nav className="sidebar-nav">
          {NAV.map(({ id, label, Icon }) => (
            <button
              key={id}
              className={`nav-item ${active === id ? 'active' : ''}`}
              onClick={() => setActive(id)}
            >
              <span className="nav-icon"><Icon /></span>
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
