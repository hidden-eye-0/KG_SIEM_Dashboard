import React, { createContext, useContext, useEffect, useState } from 'react'
import { BrowserRouter, NavLink, Navigate, Route, Routes } from 'react-router-dom'
import { api } from './services/api'
import Dashboard from './pages/Dashboard'
import Alerts from './pages/Alerts'
import AlertDetail from './pages/AlertDetail'
import Investigations from './pages/Investigations'
import InvestigationDetail from './pages/InvestigationDetail'
import KnowledgeGraph from './pages/KnowledgeGraph'
import AttackStory from './pages/AttackStory'
import ThreatIntel from './pages/ThreatIntel'
import Events from './pages/Events'
// import Models from './pages/Models'
// import Evaluation from './pages/Evaluation'
import Settings from './pages/Settings'
import Login from './pages/Login'

export const AppCtx = createContext({ config: null, health: null })
export const useApp = () => useContext(AppCtx)

const NAV = [
  ['/', '1', 'Dashboard'],
  ['/alerts', '2', 'Alerts'],
  ['/investigations', '3', 'Investigations'],
  ['/graph', '4', 'Knowledge Graph'],
  ['/story', '5', 'Attack Story'],
  ['/threat-intel', '6', 'Threat Intel'],
  ['/events', '7', 'Security Events'],
  // ['/models', '8', 'ML models'],
  // ['/evaluation', '9', 'Evaluation'],
  ['/settings', '10', 'Settings'],
]

function Shell({ children }) {
  const { config, health, user, logout } = useApp()
  const demo = config?.dataset_placeholder
  return (
    <div className="layout">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">K</div>
          <div>
            <strong>KG<span>SIEM</span></strong>
            <small>Security Operations</small>
          </div>
        </div>

        <div className="nav-label">WORKSPACE</div>
        <nav className="nav">
          {NAV.map(([to, n, label]) => (
            <NavLink key={to} to={to} end={to === '/'}>
              <span className="nav-icon">{['⌂','!','↗','◇','≡','◎','≋','▣','◒','⚙'][Number(n)-1]}</span>
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>

        <div className="sidebar-bottom">
          <div className="status-card">
            <div className="status-title"><span className="status-dot" /> SYSTEM STATUS</div>
            <div className="status-row"><span>Store</span><b>{health?.mongo?.backend || '…'}</b></div>
            <div className="status-row"><span>Graph</span><b>{health?.graph?.backend || '…'}</b></div>
            <div className="status-row"><span>Detection</span><b>{health?.gemini?.available ? 'Enhanced' : 'Heuristic'}</b></div>
            <div className="status-row"><span>Data</span><b>{demo ? 'Demo' : 'Live'}</b></div>
          </div>
          <div className="user-row">
            <div className="avatar">{(user?.username || 'A').slice(0,1).toUpperCase()}</div>
            <div className="user-meta">
              <b>{user?.username || 'Analyst'}</b>
              <small>{user?.anonymous ? 'Demo analyst' : 'Security analyst'}</small>
            </div>
            {!user?.anonymous && (
              <button className="icon-btn" title="Log out" onClick={logout}>↪</button>
            )}
          </div>
        </div>
      </aside>
      <main className="main">
        <header className="topbar">
          <div>
            <span className="eyebrow">SECURITY OPERATIONS CENTER</span>
            <span className="live-indicator"><i /> Live</span>
          </div>
          <div className="topbar-actions">
            <span className="topbar-time">Monitoring active</span>
            <button className="top-icon" title="Notifications">◌</button>
            <button className="top-icon" title="Help">?</button>
          </div>
        </header>
        {children}
      </main>
    </div>
  )
}

export default function App() {
  const [config, setConfig] = useState(null)
  const [health, setHealth] = useState(null)
  const [user, setUser] = useState(null)
  const [authError, setAuthError] = useState(null)

  const refresh = () => {
    api.config().then(setConfig).catch(() => {})
    api.health().then(setHealth).catch(() => {})
  }
  useEffect(() => {
    refresh()
    const t = setInterval(refresh, 20000)
    return () => clearInterval(t)
  }, [])
  useEffect(() => {
    api
      .me()
      .then(setUser)
      .catch((e) => setAuthError(e))
  }, [])

  const login = async (u, p) => {
    const r = await api.login(u, p)
    localStorage.setItem('token', r.access_token)
    setUser({ username: r.username, role: r.role })
    setAuthError(null)
  }
  const logout = () => {
    localStorage.removeItem('token')
    setUser(null)
    api.me().then(setUser).catch((e) => setAuthError(e))
  }

  const ctx = { config, health, user, login, logout, refresh }
  const needLogin = config?.auth_required && !user

  return (
    <AppCtx.Provider value={ctx}>
      <BrowserRouter>
        {needLogin ? (
          <Login error={authError} />
        ) : (
          <Shell>
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/alerts" element={<Alerts />} />
              <Route path="/alerts/:id" element={<AlertDetail />} />
              <Route path="/investigations" element={<Investigations />} />
              <Route path="/investigations/:id" element={<InvestigationDetail />} />
              <Route path="/graph" element={<KnowledgeGraph />} />
              <Route path="/graph/:id" element={<KnowledgeGraph />} />
              <Route path="/story" element={<AttackStory />} />
              <Route path="/story/:id" element={<AttackStory />} />
              <Route path="/threat-intel" element={<ThreatIntel />} />
              <Route path="/events" element={<Events />} />
              {/* <Route path="/models" element={<Models />} />
              <Route path="/evaluation" element={<Evaluation />} /> */}
              <Route path="/settings" element={<Settings />} />
              <Route path="/login" element={<Login error={authError} />} />
              <Route path="*" element={<Navigate to="/" />} />
            </Routes>
          </Shell>
        )}
      </BrowserRouter>
    </AppCtx.Provider>
  )
}
