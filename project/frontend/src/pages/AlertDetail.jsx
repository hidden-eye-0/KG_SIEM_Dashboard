import React, { useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { api } from '../services/api'
import { Badge, ErrorBox, KV, Loading, ProvenanceBanner, Severity, fmtTime, useAsync } from '../components/common'
import { useApp } from '../App'

export default function AlertDetail() {
  const { id } = useParams()
  const nav = useNavigate()
  const { health } = useApp()
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState(null)
  const [tick, setTick] = useState(0)
  const { loading, data: a, error } = useAsync(() => api.alert(id), [id, tick])
  const events = useAsync(() => api.alertEvents(id, 25), [id])

  const investigate = async (mode, policy) => {
    setBusy(true)
    setErr(null)
    try {
      const inv = await api.createInvestigation({ alert_id: id, mode, policy })
      nav(`/investigations/${inv._id}`)
    } catch (e) {
      setErr(e)
    } finally {
      setBusy(false)
    }
  }
  const setStatus = async (status) => {
    await api.setAlertStatus(id, status)
    setTick((t) => t + 1)
  }

  if (loading) return <Loading />
  if (error) return <ErrorBox error={error} />
  const be = a.behavioral_evidence || {}
  return (
    <div>
      <div className="page-title">
        <h1>
          <Severity level={a.severity} /> {a.attack_type} from <span className="mono">{a.source_ip}</span>
        </h1>
        <span className="sub mono">{a._id}</span>
      </div>
      <ProvenanceBanner dataSource={a.data_source} provenance={a.provenance} compact />
      <ErrorBox error={err} />
      <div className="row" style={{ marginBottom: 12 }}>
        <button disabled={busy} onClick={() => investigate('adaptive')}>
          ▶ Investigate (adaptive{health?.gemini?.available ? ', Gemini policy' : ', heuristic policy'})
        </button>
        {health?.gemini?.available && (
          <button className="secondary" disabled={busy} onClick={() => investigate('adaptive', 'heuristic')}>
            adaptive · heuristic policy
          </button>
        )}
        <button className="secondary" disabled={busy} onClick={() => investigate('baseline')}>
          baseline (fixed 3 queries)
        </button>
        <span className="spacer" />
        <select value={a.status} onChange={(e) => setStatus(e.target.value)}>
          {['open', 'investigating', 'resolved', 'false_positive', 'closed'].map((s) => (
            <option key={s}>{s}</option>
          ))}
        </select>
      </div>
      <div className="grid cols-3">
        <div className="card">
          <h3>Alert</h3>
          <KV data={{ category: a.category, predicted_label: a.predicted_label, severity: a.severity, 'model confidence (mean)': (a.confidence_mean ?? 0).toFixed(3), flows: a.event_count, first_seen: fmtTime(a.first_seen), last_seen: fmtTime(a.last_seen), protocols: (a.protocols || []).join(', '), model_version: a.model_version, data_source: a.data_source, provenance: a.provenance }} />
          <div style={{ marginTop: 8 }} className="small">
            <div className="muted">severity rationale</div>
            <ul style={{ margin: '4px 0', paddingLeft: 16 }}>
              {(a.severity_rationale || []).map((r, i) => (
                <li key={i}>{r}</li>
              ))}
            </ul>
          </div>
        </div>
        <div className="card">
          <h3>Entities</h3>
          <KV data={{ source_ip: a.source_ip, destination_ips: (a.destination_ips || []).join(', '), devices: (a.device_ids || []).join(', ') }} />
          <h3 style={{ marginTop: 14 }}>Behavioral evidence</h3>
          <div className="small muted" style={{ marginBottom: 6 }}>
            Top features of these flows vs. the benign profile (z-scores). They provide behavioral evidence associated with the labelled {a.attack_type} class; they do not prove intent.
          </div>
          <table>
            <thead>
              <tr>
                <th>feature</th>
                <th>z vs benign</th>
              </tr>
            </thead>
            <tbody>
              {(be.top_features || []).map((f) => (
                <tr key={f.feature}>
                  <td className="mono">{f.feature}</td>
                  <td>{Number(f.z_vs_benign).toFixed(2)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {a.profile?.profile_statement && <div className="small muted" style={{ marginTop: 8 }}>{a.profile.profile_statement}</div>}
        </div>
        <div className="card">
          <h3>Investigations of this alert</h3>
          {a.investigations?.length ? (
            <table>
              <thead>
                <tr>
                  <th>id</th>
                  <th>mode</th>
                  <th>status</th>
                  <th>steps</th>
                </tr>
              </thead>
              <tbody>
                {a.investigations.map((i) => (
                  <tr key={i._id} className="clickable" onClick={() => nav(`/investigations/${i._id}`)}>
                    <td className="mono small">{i._id.slice(-10)}</td>
                    <td>
                      <Badge>{i.mode}</Badge>
                    </td>
                    <td>
                      <Badge kind={i.status}>{i.status}</Badge>
                    </td>
                    <td>{i.metrics?.steps ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="muted small">none yet</div>
          )}
        </div>
      </div>
      <div className="card" style={{ marginTop: 14 }}>
        <h3>Sample of triggering events ({events.data?.items?.length || 0} of {a.event_count})</h3>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>event id</th>
                <th>time</th>
                <th>src → dst</th>
                <th>device</th>
                <th>proto</th>
                <th>prediction</th>
                <th>conf</th>
              </tr>
            </thead>
            <tbody>
              {(events.data?.items || []).map((e) => (
                <tr key={e._id}>
                  <td className="mono small">
                    <Link to={`/events?id=${e._id}`}>{e._id}</Link>
                  </td>
                  <td className="small">{fmtTime(e.timestamp)}</td>
                  <td className="mono small">
                    {e.source_ip} → {e.destination_ip}
                  </td>
                  <td className="small">{e.device_id}</td>
                  <td className="small">{e.protocol}</td>
                  <td className="small">{e.prediction?.attack_type}</td>
                  <td className="small">{(e.prediction?.confidence ?? 0).toFixed(2)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
