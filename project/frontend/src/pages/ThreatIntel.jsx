import React, { useState } from 'react'
import { api } from '../services/api'
import { Badge, ErrorBox, KV, Loading, fmtTime, useAsync } from '../components/common'
import { useApp } from '../App'

export default function ThreatIntel() {
  const { health } = useApp()
  const [tick, setTick] = useState(0)
  const cache = useAsync(() => api.ti(), [tick])
  const mitre = useAsync(() => api.mitre(), [])
  const [ind, setInd] = useState('')
  const [res, setRes] = useState(null)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState(null)
  const [interp, setInterp] = useState({})

  const lookup = async (e) => {
    e.preventDefault()
    setBusy(true)
    setErr(null)
    try {
      setRes(await api.tiLookup(ind.trim()))
      setTick((t) => t + 1)
    } catch (ex) {
      setErr(ex)
    } finally {
      setBusy(false)
    }
  }
  const interpret = async (provider) => {
    try {
      const r = await api.tiInterpret(res.indicator, provider)
      setInterp((m) => ({ ...m, [provider]: r }))
    } catch (ex) {
      setErr(ex)
    }
  }

  const providers = cache.data?.providers || {}
  return (
    <div>
      <div className="page-title">
        <h1>Threat intelligence</h1>
        <span className="sub">
          VirusTotal {providers.virustotal ? <Badge kind="ok">configured</Badge> : <Badge>not configured</Badge>} · OTX {providers.otx ? <Badge kind="ok">configured</Badge> : <Badge>not configured</Badge>} · Gemini {health?.gemini?.available ? <Badge kind="llm">on</Badge> : <Badge>off</Badge>}
        </span>
      </div>
      <div className="banner info">
        ℹ️
        <div>
          Lookups are <b>passive</b> (reputation only) and cached. Private and documentation-range addresses (RFC 1918 / RFC 5737 — all synthesized demo attackers) are never sent to
          providers. The <b>API result</b> and the optional <b>AI interpretation</b> are always shown separately; only the API result is ever used as evidence.
        </div>
      </div>
      <div className="card" style={{ marginBottom: 12 }}>
        <form className="row" onSubmit={lookup}>
          <input placeholder="IP address, domain or file hash" value={ind} onChange={(e) => setInd(e.target.value)} style={{ minWidth: 340 }} />
          <button disabled={busy || !ind.trim()}>Lookup</button>
        </form>
        <ErrorBox error={err} />
        {res && (
          <div className="split" style={{ marginTop: 12 }}>
            {['virustotal', 'otx'].map((p) => {
              const r = res[p]
              if (!r) return null
              return (
                <div key={p} className="card" style={{ background: 'var(--panel-2)' }}>
                  <h3>
                    {p} — API result <Badge kind={r.status === 'ok' ? 'ok' : r.status === 'not_configured' ? 'info' : 'medium'}>{r.status}</Badge> {r.cache_hit && <Badge>cache</Badge>}
                  </h3>
                  <div className="small muted">{r.note}</div>
                  {r.normalized && Object.keys(r.normalized).length > 0 && <KV data={r.normalized} />}
                  <div className="small muted" style={{ marginTop: 6 }}>fetched {fmtTime(r.fetched_at)}</div>
                  <div style={{ marginTop: 8 }}>
                    <button className="secondary" disabled={!health?.gemini?.available || r.status !== 'ok'} onClick={() => interpret(p)}>
                      AI interpretation (separate)
                    </button>
                    {interp[p] && (
                      <div className="claim" style={{ marginTop: 6 }}>
                        <Badge kind="llm">Gemini interpretation — not evidence</Badge>
                        <div className="small" style={{ marginTop: 4 }}>{interp[p].ai_interpretation?.text || interp[p].note}</div>
                        {interp[p].ai_interpretation?.caveats?.length > 0 && <div className="small muted">caveats: {interp[p].ai_interpretation.caveats.join(' · ')}</div>}
                      </div>
                    )}
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>

      <div className="grid cols-2">
        <div className="card">
          <h3>Cached lookups ({cache.data?.items?.length || 0})</h3>
          {cache.loading ? (
            <Loading />
          ) : (
            <div className="table-wrap" style={{ maxHeight: 420, overflow: 'auto' }}>
              <table>
                <thead>
                  <tr>
                    <th>indicator</th>
                    <th>provider</th>
                    <th>status</th>
                    <th>verdict</th>
                    <th>fetched</th>
                  </tr>
                </thead>
                <tbody>
                  {(cache.data?.items || []).map((r) => (
                    <tr key={r._id}>
                      <td className="mono small">{r.indicator}</td>
                      <td className="small">{r.provider}</td>
                      <td>
                        <Badge kind={r.status === 'ok' ? 'ok' : 'info'}>{r.status}</Badge>
                      </td>
                      <td className="small">{r.normalized?.verdict || '—'}</td>
                      <td className="small">{fmtTime(r.fetched_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
        <div className="card">
          <h3>MITRE ATT&CK curated mappings {mitre.data?.bundle_loaded ? <Badge kind="ok">verified against STIX bundle</Badge> : <Badge>bundle not downloaded — names from curated table</Badge>}</h3>
          <div className="table-wrap" style={{ maxHeight: 420, overflow: 'auto' }}>
            <table>
              <thead>
                <tr>
                  <th>attack type</th>
                  <th>technique</th>
                  <th>tactic</th>
                  <th>conf</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(mitre.data?.mappings || {}).flatMap(([t, ms]) =>
                  ms.map((m) => (
                    <tr key={t + m.technique_id}>
                      <td className="small">{t}</td>
                      <td className="small">
                        <a href={m.url} target="_blank" rel="noreferrer">
                          {m.technique_id}
                        </a>{' '}
                        {m.name}
                      </td>
                      <td className="small">{m.tactic}</td>
                      <td>
                        <Badge kind={m.confidence === 'high' ? 'ok' : 'info'}>{m.confidence}</Badge>
                      </td>
                    </tr>
                  )),
                )}
              </tbody>
            </table>
          </div>
          <div className="small muted" style={{ marginTop: 6 }}>Mappings are class-level associations; flow evidence supports the class label, not the technique's internal actions.</div>
        </div>
      </div>
    </div>
  )
}
