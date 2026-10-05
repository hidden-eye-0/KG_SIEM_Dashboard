import React, { useState } from 'react'
import { api } from '../services/api'
import { Badge, ErrorBox, KV, Loading, useAsync } from '../components/common'
import { useApp } from '../App'

export default function Settings() {
  const { config, health, refresh } = useApp()
  const ds = useAsync(() => api.datasetStatus(), [])
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState(null)
  const [err, setErr] = useState(null)

  const reseed = async (fast) => {
    if (!confirm('Re-run the offline pipeline? This clears events, alerts, investigations and reports in the current store.')) return
    setBusy(true)
    setErr(null)
    try {
      setMsg(await api.reseed(fast))
      setTimeout(refresh, 3000)
    } catch (e) {
      setErr(e)
    } finally {
      setBusy(false)
    }
  }

  if (!config || !health) return <Loading />
  return (
    <div>
      <div className="page-title">
        <h1>Settings & system status</h1>
        <span className="sub">all values come from the backend .env — secrets are never sent to the browser</span>
      </div>
      <div className="grid cols-2">
        <div className="card">
          <h3>Dataset</h3>
          {ds.data && (
            <>
              <div className={`banner ${ds.data.mode === 'demo' ? 'warn' : 'ok'}`} style={{ marginBottom: 8 }}>
                {ds.data.mode === 'demo' ? '⚠️' : '✅'}
                <div>
                  <b>{ds.data.mode === 'demo' ? 'Placeholder mode' : 'Dataset mode'}</b> — <code>DATASET_DIR={ds.data.dataset_dir}</code> · {ds.data.file_count} CSV file(s)
                  {ds.data.placeholder_note && <div className="small" style={{ marginTop: 4 }}>{ds.data.placeholder_note}</div>}
                </div>
              </div>
              {ds.data.csv_files?.length > 0 && <div className="small mono muted">{ds.data.csv_files.slice(0, 20).join(', ')}{ds.data.csv_files.length > 20 ? ' …' : ''}</div>}
              {ds.data.inspection && (
                <div className="small" style={{ marginTop: 8 }}>
                  <div className="muted">inspection summary</div>
                  <KV data={{ files: ds.data.inspection.file_count, rows: ds.data.inspection.total_rows, columns: ds.data.inspection.column_count, in_scope_labels_found: ds.data.inspection.coverage?.found_in_scope, in_scope_labels_missing: (ds.data.inspection.coverage?.missing_in_scope || []).join(', ') || 'none' }} />
                </div>
              )}
              {ds.data.preprocess_report && (
                <div className="small" style={{ marginTop: 8 }}>
                  <div className="muted">preprocessing</div>
                  <KV data={{ input_rows: ds.data.preprocess_report.input_rows, after_scope_filter: ds.data.preprocess_report.rows_after_scope_filter, duplicates_dropped: ds.data.preprocess_report.duplicates_dropped, inf_replaced: ds.data.preprocess_report.inf_cells_replaced, nan_imputed: ds.data.preprocess_report.nan_cells_imputed }} />
                </div>
              )}
            </>
          )}
          <div className="row" style={{ marginTop: 10 }}>
            <button disabled={busy} onClick={() => reseed(true)}>
              Re-run pipeline (fast)
            </button>
            <button className="secondary" disabled={busy} onClick={() => reseed(false)}>
              Re-run pipeline (full)
            </button>
            {msg && <Badge kind="ok">{msg.status}</Badge>}
          </div>
          <div className="small muted" style={{ marginTop: 6 }}>
            seed status: <b>{health.seed?.status}</b> {health.seed?.error && <span className="error">{health.seed.error}</span>}
          </div>
          <ErrorBox error={err} />
        </div>
        <div className="card">
          <h3>Runtime configuration (non-secret)</h3>
          <KV data={{ gemini_model: config.gemini_model, gemini_configured: String(config.gemini_configured), gemini_verified: health.gemini?.checked ? String(health.gemini.available) + (health.gemini.note ? ` (${health.gemini.note})` : '') : 'pending', virustotal: String(config.virustotal_configured), otx: String(config.otx_configured), store: config.mongo_backend, graph: config.graph_backend, policy_requested: config.investigation_policy_requested, policy_effective: config.investigation_policy_effective, sufficiency_threshold: config.sufficiency_threshold, auth_required: String(config.auth_required), mitre_bundle: String(health.mitre?.bundle_loaded) }} />
          <h3 style={{ marginTop: 14 }}>Investigation safeguards</h3>
          <KV data={config.budget} />
        </div>
      </div>
      <div className="card" style={{ marginTop: 14 }}>
        <h3>Store collections</h3>
        <div className="pill-list">
          {Object.entries(health.counts || {}).map(([k, v]) => (
            <Badge key={k}>
              {k}: {v}
            </Badge>
          ))}
        </div>
        <div className="small muted" style={{ marginTop: 10 }}>
          Switching to real services: set <code>MONGODB_URI</code> (Atlas), <code>NEO4J_URI/USERNAME/PASSWORD</code> (Aura), <code>GEMINI_API_KEY</code>, <code>VIRUSTOTAL_API_KEY</code>, <code>OTX_API_KEY</code> in <code>.env</code> and restart the backend. Without them the system runs fully offline with an in-process store, an in-memory graph and the heuristic policy.
        </div>
      </div>
    </div>
  )
}
