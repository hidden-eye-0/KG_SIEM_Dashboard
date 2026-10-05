import React, { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'

export const fmtTime = (t) => {
  if (!t) return '—'
  const d = new Date(t)
  return isNaN(d) ? String(t) : d.toISOString().replace('T', ' ').slice(0, 19) + 'Z'
}
export const fmtNum = (n, d = 2) => (n === null || n === undefined || isNaN(n) ? '—' : Number(n).toFixed(d))
export const pct = (n) => (n === null || n === undefined ? '—' : `${(n * 100).toFixed(0)}%`)

export function Badge({ kind, children }) {
  return <span className={`badge ${kind || ''}`}>{children}</span>
}

export function Severity({ level }) {
  return <Badge kind={level}>{String(level || '').toUpperCase()}</Badge>
}

export function ProvenanceBanner({ dataSource, provenance, compact }) {
  const synthetic = dataSource === 'synthetic_demo'
  if (!synthetic && provenance !== 'synthesized') return null
  return (
    <div className={`banner ${synthetic ? 'warn' : 'info'}`}>
      <span>{synthetic ? '⚠️' : 'ℹ️'}</span>
      <div>
        {synthetic ? (
          <>
            <b>Demonstration data.</b> No CICIoT2023 files were found in <code>DATASET_DIR</code>, so flows, models, alerts and every derived number on this page come from
            synthetic placeholder flows (<code>data_source=synthetic_demo</code>). Nothing here describes the real dataset. Copy the <code>part-*.csv</code> files into the
            dataset directory and re-run the pipeline to switch.
          </>
        ) : (
          <>
            <b>Synthesized context.</b> IP addresses, devices and timestamps are attached by the Scenario Contextualiser (<code>provenance=synthesized</code>); feature values and
            labels come from CICIoT2023 flows. Scenario ground truth is hidden from the agents and used only for evaluation.
          </>
        )}
        {!compact && synthetic && (
          <div className="small muted" style={{ marginTop: 4 }}>
            IP addresses use RFC 5737 documentation ranges and are never sent to threat-intelligence providers.
          </div>
        )}
      </div>
    </div>
  )
}

export function Loading({ text = 'Loading…' }) {
  return <div className="loading">{text}</div>
}

export function ErrorBox({ error }) {
  if (!error) return null
  return <div className="banner bad">⛔ {String(error.message || error)}</div>
}

export function KV({ data, keys }) {
  const entries = keys ? keys.map((k) => [k, data?.[k]]) : Object.entries(data || {})
  return (
    <dl className="kv">
      {entries.map(([k, v]) => (
        <React.Fragment key={k}>
          <dt>{k}</dt>
          <dd>{v === null || v === undefined ? '—' : typeof v === 'object' ? <code>{JSON.stringify(v)}</code> : String(v)}</dd>
        </React.Fragment>
      ))}
    </dl>
  )
}

export function useAsync(fn, deps = []) {
  const [state, set] = useState({ loading: true, data: null, error: null })
  useEffect(() => {
    let alive = true
    set((s) => ({ ...s, loading: true, error: null }))
    Promise.resolve()
      .then(fn)
      .then((data) => alive && set({ loading: false, data, error: null }))
      .catch((error) => alive && set({ loading: false, data: null, error }))
    return () => {
      alive = false
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps)
  return state
}

export function EvidenceIds({ ids, invId, max = 6 }) {
  if (!ids?.length) return <span className="muted small">no evidence ids</span>
  const shown = ids.slice(0, max)
  return (
    <span className="ev">
      {shown.map((id) => (
        <span key={id} style={{ marginRight: 6 }}>
          {id.startsWith('evt_') ? <Link to={`/events?id=${id}`}>{id}</Link> : id.startsWith('alr_') ? <Link to={`/alerts/${id}`}>{id}</Link> : id.startsWith('evd_') && invId ? <Link to={`/investigations/${invId}?tab=evidence&evd=${id}`}>{id}</Link> : id}
        </span>
      ))}
      {ids.length > max && <span className="muted">+{ids.length - max} more</span>}
    </span>
  )
}

export function Meter({ value }) {
  const v = Math.max(0, Math.min(1, Number(value) || 0))
  return (
    <span>
      <span className="meter">
        <i style={{ width: `${v * 100}%` }} />
      </span>
      <span className="small">{fmtNum(v)}</span>
    </span>
  )
}

export function Pager({ page, pageSize, total, onChange }) {
  const pages = Math.max(1, Math.ceil((total || 0) / pageSize))
  return (
    <div className="row small" style={{ marginTop: 8 }}>
      <button className="secondary" disabled={page <= 1} onClick={() => onChange(page - 1)}>
        ‹ Prev
      </button>
      <span className="muted">
        page {page} / {pages} · {total} rows
      </span>
      <button className="secondary" disabled={page >= pages} onClick={() => onChange(page + 1)}>
        Next ›
      </button>
    </div>
  )
}
