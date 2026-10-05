import React from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { api } from '../services/api'
import { Badge, ErrorBox, Loading, ProvenanceBanner, Severity, fmtTime, useAsync } from '../components/common'
import { useApp } from '../App'

const CAT_COLORS = { DDoS: '#ff5c5c', DoS: '#ff8c42', Reconnaissance: '#4f9cf9', 'Web-Based': '#b48ef7', 'Brute Force': '#f5b942', Spoofing: '#3fc1c9', Benign: '#2ecc71' }

export default function Dashboard() {
  // const { health } = useApp()
  const nav = useNavigate()
  const ev = useAsync(() => api.eventsSummary(), [])
  const al = useAsync(() => api.alertsSummary(), [])
  const recent = useAsync(() => api.alerts({ page_size: 8, sort: '-created_at' }), [])
  const invs = useAsync(() => api.investigations({ page_size: 6 }), [])
  const tl = useAsync(() => api.eventsTimeline({ bucket_minutes: 15 }), [])

  if (ev.loading || al.loading) return <Loading />
  const err = ev.error || al.error
  if (err) return <ErrorBox error={err} />

  const bySev = Object.fromEntries((al.data.by_severity || []).map((r) => [r._id, r.count]))
  const cats = Array.from(new Set((tl.data?.points || []).map((p) => p.category).filter(Boolean)))
  const buckets = {}
  for (const p of tl.data?.points || []) {
    const k = p.bucket_ms
    buckets[k] = buckets[k] || { t: fmtTime(new Date(k)).slice(11, 16) }
    buckets[k][p.category] = p.count
  }
  const series = Object.keys(buckets).sort((a, b) => a - b).map((k) => buckets[k])

  return (
    <div>
      <div className="page-title">
        
        {/* <h1>SOC Dashboard</h1>
        <span className="sub">
          pipeline <b>{health?.pipeline_mode}</b> · seed {health?.seed?.status} · model {health?.seed?.model_version || '—'}
        </span> */}
      <div>
        <h1>Security Operations Center</h1>
        <span className="sub">
          Monitor security activity, alerts, and investigations
        </span>
      </div>
      <Badge kind="success">Monitoring active</Badge>

        
      </div>
      {/* <ProvenanceBanner dataSource={ev.data.data_source} provenance={ev.data.provenance} /> */}
      <div className="grid cols-4">
        <div className="card">
          <h3>Security Events</h3>
          <div className="kpi">
            {ev.data.total.toLocaleString()}
            <small>
              {fmtTime(ev.data.time_span?.first)} → {fmtTime(ev.data.time_span?.last)}
            </small>
          </div>
        </div>
        <div className="card">
          <h3>Alerts</h3>
          <div className="kpi">
            {al.data.total}
            <small>
              {['critical', 'high', 'medium', 'low', 'info'].map((s) => (
                <span key={s} style={{ marginRight: 6 }}>
                  <Severity level={s} /> {bySev[s] || 0}
                </span>
              ))}
            </small>
          </div>
        </div>
        <div className="card">
          <h3>Investigations</h3>
          <div className="kpi">
            {invs.data?.total ?? '—'}
            <small>{(al.data.by_status || []).map((r) => `${r._id}: ${r.count}`).join(' · ') || 'no alerts triaged yet'}</small>
          </div>
        </div>
        <div className="card">
          <h3>Detection Status</h3>
          <div className="kpi" style={{ fontSize: 16 }}>
            <Badge kind="success">Active</Badge>
            <small>
              Threat detection and alert correlation are running normally
            </small>
          </div>
        </div>
        {/* <div className="card">
          <h3>Agent runtime</h3>
          <div className="kpi" style={{ fontSize: 16 }}>
            {health?.gemini?.available ? <Badge kind="llm">Gemini {health.gemini.model}</Badge> : <Badge>heuristic policy</Badge>}
            <small>
              graph {health?.graph?.backend} · store {health?.mongo?.backend} · TI {health?.threat_intel?.virustotal ? 'VT' : ''} {health?.threat_intel?.otx ? 'OTX' : ''} {!health?.threat_intel?.virustotal && !health?.threat_intel?.otx ? 'not configured' : ''}
            </small>
          </div>
        </div> */}
      </div>

      <div className="grid cols-2" style={{ marginTop: 14 }}>
        <div className="card">
          <h3>Security Activity</h3>
          <div style={{ height: 260 }}>
            <ResponsiveContainer>
              <BarChart data={series}>
                <CartesianGrid stroke="#22304a" />
                <XAxis dataKey="t" stroke="#93a4c0" fontSize={11} />
                <YAxis stroke="#93a4c0" fontSize={11} />
                <Tooltip contentStyle={{ background: '#111a2b', border: '1px solid #22304a' }} />
                <Legend />
                {cats.map((c) => (
                  <Bar key={c} dataKey={c} stackId="a" fill={CAT_COLORS[c] || '#888'} />
                ))}
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
        <div className="card">
          <h3>Threat Categories</h3>
          <div style={{ height: 260 }}>
            <ResponsiveContainer>
              <BarChart data={(ev.data.by_attack_type || []).slice(0, 14).map((r) => ({ name: r._id, count: r.count }))} layout="vertical" margin={{ left: 40 }}>
                <CartesianGrid stroke="#22304a" />
                <XAxis type="number" stroke="#93a4c0" fontSize={11} />
                <YAxis type="category" dataKey="name" width={130} stroke="#93a4c0" fontSize={11} />
                <Tooltip contentStyle={{ background: '#111a2b', border: '1px solid #22304a' }} />
                <Bar dataKey="count" fill="#4f9cf9" />
              </BarChart>
            </ResponsiveContainer>
          </div>
          {/* <div className="small muted">Counts are model predictions over the ingested flows, not dataset label statistics.</div> */}
        </div>
      </div>

      <div className="grid cols-2" style={{ marginTop: 14 }}>
        <div className="card">
          <h3>Recent Alerts</h3>
          <table>
            <thead>
              <tr>
                <th>severity</th>
                <th>attack type</th>
                <th>source</th>
                <th>flows</th>
                <th>first seen</th>
              </tr>
            </thead>
            <tbody>
              {(recent.data?.items || []).map((a) => (
                <tr key={a._id} className="clickable" onClick={() => nav(`/alerts/${a._id}`)}>
                  <td>
                    <Severity level={a.severity} />
                  </td>
                  <td>{a.attack_type}</td>
                  <td className="mono">{a.source_ip}</td>
                  <td>{a.event_count}</td>
                  <td className="small">{fmtTime(a.first_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="small" style={{ marginTop: 6 }}>
            <Link to="/alerts">all alerts →</Link>
          </div>
        </div>
        <div className="card">
          <h3>Recent Investigations</h3>
          {invs.data?.items?.length ? (
            <table>
              <thead>
                <tr>
                  <th>Investigation</th>
                  <th>Status</th>
                  <th>Severity</th>
                  <th>Updated</th>
                </tr>
              </thead>
              <tbody>
                {invs.data.items.map((i) => (
                  <tr key={i._id} className="clickable" onClick={() => nav(`/investigations/${i._id}`)}>
                    <td className="mono small">{i._id.slice(-10)}</td>
                    <td>
                      <Badge>{i.mode}</Badge>
                    </td>
                    <td>
                      <Badge kind={i.status}>{i.status}</Badge>
                    </td>
                    <td>{i.metrics?.steps ?? '—'}</td>
                    <td>{i.metrics?.stage_count ?? '—'} stages</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="muted small">No investigations yet. Select an alert and click “Investigate”.</div>
          )}
        </div>
      </div>
    </div>
  )
}
