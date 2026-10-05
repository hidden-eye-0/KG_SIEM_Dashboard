import React, { useState } from 'react'
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { api } from '../services/api'
import { Badge, ErrorBox, KV, Loading, ProvenanceBanner, fmtNum, fmtTime, useAsync } from '../components/common'

export default function Models() {
  const models = useAsync(() => api.models(), [])
  const latest = useAsync(() => api.model('latest'), [])
  const g = useAsync(() => api.globalProfile(), [])
  const profiles = useAsync(() => api.profiles(), [])
  const [sel, setSel] = useState(null)
  const prof = useAsync(() => (sel ? api.profile(sel) : null), [sel])
  const [modelName, setModelName] = useState(null)

  if (models.loading || latest.loading) return <Loading />
  if (models.error) return <ErrorBox error={models.error} />
  const m = latest.data
  if (!m) return <div className="card muted">No trained model yet — the pipeline seeds one at startup.</div>
  const names = Object.keys(m.models || {})
  const mn = modelName || m.primary_model || names[0]
  const r = m.models[mn]
  const perClass = (r?.test?.per_class || []).map((c) => ({ name: c.class, f1: +(c.f1 * 100).toFixed(1), precision: c.precision, recall: c.recall, support: c.support }))
  const cmObj = r?.test?.confusion_matrix
  const cm = Array.isArray(cmObj) ? cmObj : cmObj?.matrix
  const classes = (Array.isArray(cmObj) ? m.classes : cmObj?.labels) || m.classes || []
  const imp = g.data?.global_importance || {}
  const top10 = g.data?.global_top10 || {}
  const topFeatures = Array.isArray(top10) ? top10 : Array.from(new Set(Object.values(top10).flat()))
  const impRows = topFeatures
    .map((f) => ({ feature: f, rf: imp.rf_impurity?.[f], perm: imp.rf_permutation?.[f], xgb: imp.xgb_gain?.[f], shap: imp.shap_mean_abs?.[f] ?? imp.shap?.[f], votes: Object.values(top10).filter((l) => Array.isArray(l) && l.includes(f)).length }))
    .sort((a, b) => b.votes - a.votes || (b.rf || 0) - (a.rf || 0))

  return (
    <div>
      <div className="page-title">
        <h1>ML models & behavioral profiles</h1>
        <span className="sub">
          version {m.version} · trained {fmtTime(m.created_at)} · primary <Badge kind="ok">{m.primary_model}</Badge> ({m.selection_rule})
        </span>
      </div>
      <ProvenanceBanner dataSource={m.data_source} />
      <div className="grid cols-4">
        <div className="card">
          <h3>Split</h3>
          <div className="kpi" style={{ fontSize: 18 }}>
            {m.n_train?.toLocaleString()} / {m.n_val?.toLocaleString()} / {m.n_test?.toLocaleString()}
            <small>train / val / test (stratified 70/15/15, seed {m.seed})</small>
          </div>
        </div>
        {names.map((n) => (
          <div key={n} className="card clickable" onClick={() => setModelName(n)} style={{ cursor: 'pointer', outline: mn === n ? '1px solid var(--accent)' : 'none' }}>
            <h3>{n}</h3>
            <div className="kpi" style={{ fontSize: 18 }}>
              macro-F1 {fmtNum(m.models[n].test?.macro_f1, 4)}
              <small>
                acc {fmtNum(m.models[n].test?.accuracy, 4)} · val F1 {fmtNum(m.models[n].validation?.macro_f1, 4)} · {m.models[n].inference_us_per_row} µs/row · train {m.models[n].train_seconds}s
              </small>
            </div>
          </div>
        ))}
        <div className="card">
          <h3>Classes</h3>
          <div className="kpi" style={{ fontSize: 18 }}>
            {classes.length}
            <small>{m.feature_columns?.length} features · Mirai & out-of-scope labels excluded</small>
          </div>
        </div>
      </div>

      <div className="grid cols-2" style={{ marginTop: 14 }}>
        <div className="card">
          <h3>Per-class F1 on the test split — {mn}</h3>
          <div style={{ height: 420 }}>
            <ResponsiveContainer>
              <BarChart data={perClass} layout="vertical" margin={{ left: 60 }}>
                <CartesianGrid stroke="#22304a" />
                <XAxis type="number" domain={[0, 100]} stroke="#93a4c0" fontSize={11} />
                <YAxis type="category" dataKey="name" width={150} stroke="#93a4c0" fontSize={10} />
                <Tooltip contentStyle={{ background: '#111a2b', border: '1px solid #22304a' }} />
                <Bar dataKey="f1" fill="#4f9cf9" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
        <div className="card">
          <h3>Feature importance — three methods compared (global)</h3>
          <div className="small muted" style={{ marginBottom: 6 }}>
            Method agreement (rank-biased overlap, top-10): {Object.entries(g.data?.method_agreement || {}).map(([k, v]) => `${k}=${fmtNum(v)}`).join(' · ') || '—'} · SHAP {g.data?.shap_available ? 'available' : 'not computed'}
          </div>
          <table>
            <thead>
              <tr>
                <th>feature</th>
                <th>in top-10 of</th>
                <th>RF impurity</th>
                <th>RF permutation</th>
                <th>XGB gain</th>
                <th>SHAP |mean|</th>
              </tr>
            </thead>
            <tbody>
              {impRows.map((x) => (
                <tr key={x.feature}>
                  <td className="mono">{x.feature}</td>
                  <td>{x.votes}/{Object.keys(top10).length} methods</td>
                  <td>{fmtNum(x.rf, 4)}</td>
                  <td>{fmtNum(x.perm, 4)}</td>
                  <td>{fmtNum(x.xgb, 4)}</td>
                  <td>{fmtNum(x.shap, 4)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {g.data?.feature_reduction?.length > 0 && (
            <div className="small" style={{ marginTop: 8 }}>
              <div className="muted">Feature-reduction experiment (top-k consensus features → macro-F1):</div>
              {g.data.feature_reduction.map((f) => (
                <span key={f.k} style={{ marginRight: 10 }}>
                  k={f.k}: {fmtNum(f.macro_f1, 4)}
                </span>
              ))}
            </div>
          )}
        </div>
      </div>

      {cm && (
        <div className="card" style={{ marginTop: 14 }}>
          <h3>Confusion matrix (test) — rows = true, columns = predicted</h3>
          <div className="table-wrap">
            <table className="small">
              <thead>
                <tr>
                  <th></th>
                  {classes.map((c) => (
                    <th key={c} style={{ writingMode: 'vertical-rl', fontSize: 9, padding: 2 }}>
                      {c}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {cm.map((row, i) => {
                  const total = row.reduce((a, b) => a + b, 0) || 1
                  return (
                    <tr key={i}>
                      <td style={{ fontSize: 10, whiteSpace: 'nowrap' }}>{classes[i]}</td>
                      {row.map((v, j) => (
                        <td key={j} style={{ padding: 2, textAlign: 'center', fontSize: 10, background: v ? `rgba(79,156,249,${Math.min(0.9, 0.15 + (v / total) * 0.85)})` : 'transparent' }}>
                          {v || ''}
                        </td>
                      ))}
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <div className="grid cols-2" style={{ marginTop: 14 }}>
        <div className="card">
          <h3>Attack-specific behavioral profiles ({profiles.data?.length || 0})</h3>
          <div className="table-wrap" style={{ maxHeight: 420, overflow: 'auto' }}>
            <table>
              <thead>
                <tr>
                  <th>attack type</th>
                  <th>category</th>
                  <th>top features (consensus)</th>
                  <th>protocols</th>
                </tr>
              </thead>
              <tbody>
                {(profiles.data || []).map((p) => (
                  <tr key={p._id} className="clickable" onClick={() => setSel(p._id)}>
                    <td>{p.attack_type}</td>
                    <td className="small">{p.category}</td>
                    <td className="small mono">{(p.top_features || []).slice(0, 5).join(', ')}</td>
                    <td className="small">{(p.dominant_protocols || []).join(', ')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
        <div className="card">
          <h3>Profile detail</h3>
          {!sel && <div className="muted small">Select a profile. Profiles are built from the trained models (RF/XGB importance + SHAP where available) and per-class feature statistics — they describe behavioral evidence associated with the labelled class, not proof of an attack.</div>}
          {prof.data && (
            <div>
              <div style={{ marginBottom: 8 }}>{prof.data.profile_statement}</div>
              <KV data={{ raw_label: prof.data.raw_label, samples_train: prof.data.n_samples_train, dominant_protocols: (prof.data.dominant_protocols || []).join(', '), feature_groups: JSON.stringify(prof.data.feature_group_scores) }} />
              <table style={{ marginTop: 8 }}>
                <thead>
                  <tr>
                    <th>feature</th>
                    <th>consensus</th>
                    <th>class mean</th>
                    <th>benign mean</th>
                    <th>z</th>
                  </tr>
                </thead>
                <tbody>
                  {(prof.data.top_features || []).map((f) => {
                    const s = prof.data.feature_stats?.[f] || {}
                    return (
                      <tr key={f}>
                        <td className="mono">{f}</td>
                        <td>{fmtNum(prof.data.consensus_scores?.[f])}</td>
                        <td>{fmtNum(s.class_mean, 3)}</td>
                        <td>{fmtNum(s.benign_mean, 3)}</td>
                        <td>{fmtNum(s.z)}</td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
