import React, { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { api } from '../services/api'
import { Badge, ErrorBox, Loading, fmtNum, fmtTime, pct, useAsync } from '../components/common'

const METRICS = [
  ['latency_ms', 'wall time (ms)', 0],
  ['steps', 'steps', 1],
  ['db_queries', 'DB queries', 1],
  ['events_retrieved', 'events retrieved', 0],
  ['llm_calls', 'LLM calls', 1],
  ['ti_lookups', 'TI lookups', 1],
  ['graph_nodes', 'graph nodes', 1],
  ['evidence_precision', 'evidence precision (vs hidden scenario)', 3],
  ['evidence_recall', 'evidence recall (scenario attack flows found)', 3],
  ['stage_recall', 'chain stage recall', 3],
  ['stage_precision', 'chain stage precision', 3],
  ['order_agreement', 'stage order agreement', 3],
  ['chain_complete_rate', 'chain complete rate', 3],
  ['claims', 'report claims', 1],
  ['claim_evidence_rate', 'claims with evidence ids', 3],
  ['grounding_pass_rate', 'narrative grounding pass rate', 3],
  ['hallucinated_ids_per_report', 'unknown ids/IPs per narrative', 2],
]

export default function Evaluation() {
  const [tick, setTick] = useState(0)
  const runs = useAsync(() => api.evalRuns(), [tick])
  const [sel, setSel] = useState(null)
  const run = useAsync(() => (sel ? api.evalRun(sel) : null), [sel])
  const [n, setN] = useState(6)
  const [job, setJob] = useState(null)
  const [err, setErr] = useState(null)

  useEffect(() => {
    if (!sel && runs.data?.length) setSel(runs.data[0]._id)
  }, [runs.data])

  useEffect(() => {
    if (!job || job.status !== 'running') return
    const t = setInterval(() => {
      api.evalJob(job.job_id).then((j) => {
        setJob({ ...job, ...j })
        if (j.status !== 'running') {
          setTick((x) => x + 1)
          if (j.run_id) setSel(j.run_id)
        }
      })
    }, 2000)
    return () => clearInterval(t)
  }, [job])

  const start = async () => {
    setErr(null)
    try {
      const j = await api.runEvaluation({ n_alerts: n, name: `ui run ${new Date().toISOString().slice(0, 16)}` })
      setJob(j)
    } catch (e) {
      setErr(e)
    }
  }

  const summary = run.data?.summary || {}
  const arms = Object.keys(summary)
  const chart = ['steps', 'db_queries', 'evidence_recall', 'stage_recall', 'chain_complete_rate', 'claim_evidence_rate'].map((k) => ({ metric: k, ...Object.fromEntries(arms.map((a) => [a, summary[a]?.[k] ?? 0])) }))

  return (
    <div>
      <div className="page-title">
        <h1>Evaluation — adaptive vs fixed-query baseline</h1>
        <span className="sub">paired runs on the same alerts · ground truth from the scenario contextualiser, hidden from the agents</span>
      </div>
      <div className="card" style={{ marginBottom: 12 }}>
        <div className="row">
          <label className="muted small">alerts (one per category, round-robin)</label>
          <input type="number" min={1} max={30} value={n} onChange={(e) => setN(+e.target.value)} style={{ width: 80 }} />
          <button onClick={start} disabled={job?.status === 'running'}>
            {job?.status === 'running' ? 'running…' : 'Run paired comparison'}
          </button>
          {job && <Badge kind={job.status === 'completed' ? 'ok' : job.status}>{job.status}</Badge>}
          <span className="spacer" />
          <label className="muted small">run</label>
          <select value={sel || ''} onChange={(e) => setSel(e.target.value)} style={{ minWidth: 300 }}>
            {(runs.data || []).map((r) => (
              <option key={r._id} value={r._id}>
                {fmtTime(r.created_at)} · {r.name} · {r.alert_ids?.length} alerts
              </option>
            ))}
          </select>
        </div>
        <ErrorBox error={err} />
      </div>

      {run.loading && <Loading />}
      {run.data && (
        <>
          <div className="grid cols-2">
            <div className="card">
              <h3>Summary (means over completed investigations)</h3>
              <table>
                <thead>
                  <tr>
                    <th>metric</th>
                    {arms.map((a) => (
                      <th key={a}>
                        {a} (n={summary[a]?.n})
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {METRICS.map(([k, label, d]) => (
                    <tr key={k}>
                      <td className="small">{label}</td>
                      {arms.map((a) => (
                        <td key={a}>{summary[a]?.[k] === null || summary[a]?.[k] === undefined ? '—' : fmtNum(summary[a][k], d)}</td>
                      ))}
                    </tr>
                  ))}
                  <tr>
                    <td className="small">termination reasons</td>
                    {arms.map((a) => (
                      <td key={a} className="small">
                        {Object.entries(summary[a]?.termination_reasons || {}).map(([k, v]) => `${k}:${v}`).join(' ')}
                      </td>
                    ))}
                  </tr>
                </tbody>
              </table>
            </div>
            <div className="card">
              <h3>Selected metrics</h3>
              <div style={{ height: 300 }}>
                <ResponsiveContainer>
                  <BarChart data={chart}>
                    <CartesianGrid stroke="#22304a" />
                    <XAxis dataKey="metric" stroke="#93a4c0" fontSize={10} />
                    <YAxis stroke="#93a4c0" fontSize={11} />
                    <Tooltip contentStyle={{ background: '#111a2b', border: '1px solid #22304a' }} />
                    <Legend />
                    {arms.map((a, i) => (
                      <Bar key={a} dataKey={a} fill={['#4f9cf9', '#f5b942', '#b48ef7'][i % 3]} />
                    ))}
                  </BarChart>
                </ResponsiveContainer>
              </div>
              <div className="small muted">
                <ul style={{ paddingLeft: 16, margin: 0 }}>
                  {(run.data.notes || []).map((x, i) => (
                    <li key={i}>{x}</li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
          <div className="card table-wrap" style={{ marginTop: 14 }}>
            <h3>Per-investigation rows</h3>
            <table>
              <thead>
                <tr>
                  <th>mode</th>
                  <th>alert</th>
                  <th>scenario (hidden GT)</th>
                  <th>steps</th>
                  <th>queries</th>
                  <th>events</th>
                  <th>ev. P</th>
                  <th>ev. R</th>
                  <th>truth stages</th>
                  <th>predicted stages</th>
                  <th>stage R/P</th>
                  <th>claims</th>
                  <th>stop</th>
                </tr>
              </thead>
              <tbody>
                {(run.data.rows || []).map((r) => (
                  <tr key={r.investigation_id}>
                    <td>
                      <Badge>{r.mode}</Badge>
                    </td>
                    <td className="small">
                      <Link to={`/investigations/${r.investigation_id}`}>{r.alert_attack_type}</Link>
                    </td>
                    <td className="small">{r.scenario || <span className="muted">single-stage / background</span>}</td>
                    <td>{r.cost?.steps}</td>
                    <td>{r.cost?.db_queries}</td>
                    <td>{r.cost?.events_retrieved}</td>
                    <td>{fmtNum(r.evidence?.precision)}</td>
                    <td>{fmtNum(r.evidence?.recall)}</td>
                    <td className="small">{(r.chain?.truth_stages || []).join(' → ')}</td>
                    <td className="small">
                      {(r.chain?.predicted_stages || []).join(' → ')}
                      {r.chain?.extra_stages?.length ? <span className="muted"> (+{r.chain.extra_stages.join(', ')})</span> : ''}
                    </td>
                    <td>
                      {pct(r.chain?.stage_recall)} / {pct(r.chain?.stage_precision)}
                    </td>
                    <td>
                      {r.report?.claims_with_evidence}/{r.report?.claims}
                    </td>
                    <td className="small">{r.cost?.termination_reason}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
      {!run.loading && !run.data && <div className="card muted">No evaluation runs yet. Click “Run paired comparison”.</div>}
    </div>
  )
}
