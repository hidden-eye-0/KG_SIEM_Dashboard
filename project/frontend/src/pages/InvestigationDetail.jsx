import React, { useEffect, useMemo, useRef, useState } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { api, streamInvestigation } from '../services/api'
import { Badge, ErrorBox, EvidenceIds, KV, Loading, Meter, Severity, fmtNum, fmtTime } from '../components/common'
import GraphView from '../components/GraphView'

const AGENT_COLORS = { AlertInvestigationAgent: '#4f9cf9', KnowledgeGraphAgent: '#2ecc71', AdaptiveEvidenceAgent: '#f5b942', ThreatIntelligenceAgent: '#ff8c42', AttackReconstructionAgent: '#b48ef7', AttackStoryReportAgent: '#e05cff' }

export default function InvestigationDetail() {
  const { id } = useParams()
  const [sp, setSp] = useSearchParams()
  const tab = sp.get('tab') || 'live'
  const [doc, setDoc] = useState(null)
  const [error, setError] = useState(null)
  const [live, setLive] = useState([])
  const [summary, setSummary] = useState(null)
  const [graphKey, setGraphKey] = useState(0)
  const logRef = useRef(null)

  const load = () =>
    api
      .investigation(id, true)
      .then((d) => {
        setDoc(d)
        setLive(d.steps || [])
      })
      .catch(setError)

  useEffect(() => {
    load()
  }, [id])

  useEffect(() => {
    if (!doc || ['completed', 'failed', 'stopped'].includes(doc.status)) return
    const close = streamInvestigation(id, {
      agent_action: (ev) => {
        if (ev.replay) return
        setLive((l) => [...l, ev.action])
        if (ev.action.node === 'update_graph' || ev.action.node === 'build_initial_graph') setGraphKey((k) => k + 1)
      },
      state: (ev) => setSummary(ev.summary),
      done: () => setTimeout(load, 400),
    })
    return close
  }, [id, doc?.status])

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight
  }, [live.length])

  if (error) return <ErrorBox error={error} />
  if (!doc) return <Loading />
  const st = doc.state || {}
  const running = doc.status === 'running'
  const hyp = summary?.hypothesis || st.current_hypothesis?.statement
  const conf = summary?.confidence ?? st.confidence
  const suff = summary?.sufficiency || st.sufficiency || {}
  const setTab = (t) => setSp({ tab: t })

  return (
    <div>
      <div className="page-title">
        {/* <h1>
          Investigation <span className="mono">{id.slice(-12)}</span> <Badge>{doc.mode}</Badge> <Badge>{doc.policy} policy</Badge> <Badge kind={doc.status}>{doc.status}</Badge>
        </h1> */}
        <h1>
          Security Investigation{' '}
          <span className="mono">{id.slice(-12)}</span>{' '}
          <Badge kind={doc.status}>{doc.status}</Badge>
        </h1>
        <span className="sub">
          Related alert:{' '}
          <Link to={`/alerts/${doc.alert_id}`}>
            {doc.alert_summary?.attack_type || 'Security Alert'}
            {doc.alert_summary?.source_ip
              ? ` · ${doc.alert_summary.source_ip}`
              : ''}
          </Link>
        {/* <span className="sub">
          alert <Link to={`/alerts/${doc.alert_id}`}>{doc.alert_summary?.attack_type} from {doc.alert_summary?.source_ip}</Link> */}
          {running && (
            <button className="danger" style={{ marginLeft: 10 }} onClick={() => api.stopInvestigation(id)}>
              stop
            </button>
          )}
        </span>
      </div>
      {doc.status === 'failed' && <div className="banner bad">⛔ {doc.error}</div>}

      <div className="grid cols-4" style={{ marginBottom: 12 }}>
        {/* <div className="card"> */}
          {/* <h3>Progress</h3>
          <div className="kpi">
            {summary?.step ?? st.investigation_step ?? 0} <small>of max {st.budget?.max_steps} steps · {st.budget?.db_queries ?? 0} queries · {st.budget?.events_retrieved ?? 0} events · {st.budget?.llm_calls_used ?? 0} LLM calls</small>
          </div>
        </div> */}
        <div className="card">
  <h3>Investigation Progress</h3>

      <div className="kpi">
        {summary?.step ?? st.investigation_step ?? 0}
        <small>
          investigation steps completed
        </small>
      </div>
    </div>
        <div className="card">
          <h3>Assessment confidence</h3>
          <div className="kpi">
            {fmtNum(conf)}
              <small>
                Confidence in the current security assessment
              </small>
          </div>
        </div>
        <div className="card">
          <h3>Sufficiency</h3>
          <div className="kpi">
            {fmtNum(suff.score)} <small>
              Evidence coverage {fmtNum(suff.coverage)}
              · Open issues {suff.open_critical ?? 0}
            </small>
          </div>
          <div className="progress" style={{ marginTop: 6 }}>
            <div style={{ width: `${(suff.score || 0) * 100}%` }} />
          </div>
        </div>
        {/* <div className="card">
          <h3>Outcome</h3>
          <div className="kpi" style={{ fontSize: 16 }}>
            {st.termination_reason ? <Badge>{st.termination_reason}</Badge> : <Badge kind="running">in progress</Badge>}
            <small>
              graph {summary?.graph?.node_count ?? st.graph_state?.node_count ?? 0} nodes / {summary?.graph?.edge_count ?? st.graph_state?.edge_count ?? 0} edges · {st.attack_chain?.stage_count ?? '—'} chain stages
            </small>
          </div>
          {doc.status === 'completed' && (
            <div className="row small" style={{ marginTop: 6 }}>
              <Link to={`/story/${id}`}>attack story →</Link>
              <Link to={`/graph/${id}`}>full graph →</Link>
            </div>
          )}
        </div> */}
        <div className="card">
          <h3>Outcome</h3>

          <div className="kpi" style={{ fontSize: 16 }}>
            {st.termination_reason ? (
              <Badge>{st.termination_reason}</Badge>
            ) : (
              <Badge kind="running">In progress</Badge>
            )}

            <small>
              Investigation assessment and supporting evidence
            </small>
          </div>

          {doc.status === 'completed' && (
            <div className="row small" style={{ marginTop: 6 }}>
              <Link to={`/story/${id}`}>View attack story →</Link>
              <Link to={`/graph/${id}`}>View knowledge graph →</Link>
            </div>
          )}
        </div>
      </div>

      <div className="card" style={{ marginBottom: 12 }}>
        <h3>Current hypothesis</h3>
        <div>{hyp || '—'}</div>
        {st.current_hypothesis?.key_questions?.length > 0 && (
          <div className="small muted" style={{ marginTop: 6 }}>
            key questions: {st.current_hypothesis.key_questions.join(' · ')}
          </div>
        )}
        {st.current_hypothesis?.contradictions?.length > 0 && <div className="small" style={{ marginTop: 6, color: '#ffd98a' }}>contradictions noted: {st.current_hypothesis.contradictions.join(' · ')}</div>}
      </div>

      <div className="tabs">
        {[
          ['live', 'Agent activity'],
          ['gaps', 'Evidence gaps & decisions'],
          ['evidence', 'Evidence'],
          ['graph', 'Knowledge graph'],
          ['chain', 'Attack chain'],
          ['state', 'Raw state'],
        ].map(([k, l]) => (
          <button key={k} className={tab === k ? 'active' : ''} onClick={() => setTab(k)}>
            {l}
          </button>
        ))}
      </div>

      {tab === 'live' && (
        <div className="card">
          <h3>
            Agent activity log ({live.length} actions{running ? ' · streaming' : ''})
          </h3>
          <div className="log" ref={logRef}>
            {live.map((a, i) => (
              <div key={i} className="log-item">
                <span className="muted">#{a.step}</span>
                <span className="agent" style={{ color: AGENT_COLORS[a.agent] || '#93a4c0' }}>
                  {a.agent.replace('Agent', '')}
                  {a.llm_used && <Badge kind="llm">LLM</Badge>}
                </span>
                <span>
                  <span className="title">{a.title}</span>
                  {a.tool && <code style={{ marginLeft: 6 }}>{a.tool}</code>}
                  <div className="detail">{a.detail}</div>
                  {a.evidence_ids?.length > 0 && (
                    <div className="small">
                      <EvidenceIds ids={a.evidence_ids} invId={id} />
                    </div>
                  )}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {tab === 'gaps' && <GapsTab st={st} />}
      {tab === 'evidence' && <EvidenceTab id={id} st={st} focus={sp.get('evd')} />}
      {tab === 'graph' && (
        <div className="card">
          <GraphView invId={id} refreshKey={graphKey} />
        </div>
      )}
      {tab === 'chain' && <ChainTab st={st} id={id} />}
      {tab === 'state' && (
        <div className="card">
          <h3>Investigation state (LangGraph)</h3>
          <div className="small muted" style={{ marginBottom: 6 }}>
            Persisted after every node. Evidence records are referenced by id (never copied into the state); ground truth is never present.
          </div>
          <pre className="pre" style={{ maxHeight: 700 }}>
            {JSON.stringify({ ...st, agent_log: `[${(st.agent_log || []).length} actions]`, evidence: (st.evidence || []).map((e) => ({ ...e, record_ids: `[${e.record_ids?.length || 0} ids]` })) }, null, 1)}
          </pre>
        </div>
      )}
    </div>
  )
}

function GapsTab({ st }) {
  const gaps = st.missing_evidence || []
  const cands = st.candidate_actions || []
  const decisions = (st.agent_log || []).filter((a) => a.node === 'decide_action')
  return (
    <div className="grid cols-2">
      <div className="card">
        <h3>Evidence requirements / gaps (state-dependent)</h3>
        <table>
          <thead>
            <tr>
              <th>requirement</th>
              <th>priority</th>
              <th>status</th>
              <th>resolved by</th>
            </tr>
          </thead>
          <tbody>
            {gaps.map((g) => (
              <tr key={g.gap_id}>
                <td>
                  <div>{g.description}</div>
                  <div className="small muted mono">{g.requirement_id}</div>
                </td>
                <td>
                  <Badge kind={g.priority === 'critical' ? 'critical' : g.priority === 'high' ? 'high' : 'info'}>{g.priority}</Badge>
                </td>
                <td>
                  <Badge kind={g.status === 'resolved' ? 'ok' : g.status === 'unresolvable' ? 'failed' : 'running'}>{g.status}</Badge>
                </td>
                <td className="small mono">{(g.resolved_by || []).join(', ')}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <h3 style={{ marginTop: 14 }}>Candidate actions at last assessment</h3>
        <table>
          <thead>
            <tr>
              <th>tool</th>
              <th>rationale</th>
              <th>gain</th>
              <th>cost</th>
              <th>utility</th>
            </tr>
          </thead>
          <tbody>
            {cands.map((c) => (
              <tr key={c.action_id}>
                <td>
                  <code>{c.tool}</code>
                </td>
                <td className="small">{c.rationale}</td>
                <td>{c.expected_gain}</td>
                <td>{c.cost}</td>
                <td>
                  <b>{c.utility}</b>
                </td>
              </tr>
            ))}
            {!cands.length && (
              <tr>
                <td colSpan={5} className="muted small">
                  none (investigation finished or no relevant evidence left to request)
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      <div className="card">
        <h3>Decision trace (why each query was chosen)</h3>
        {decisions.map((d, i) => (
          <div key={i} className="claim">
            <div>
              <b>#{d.step}</b> {d.title} {d.llm_used && <Badge kind="llm">LLM</Badge>}
            </div>
            <div className="small muted">{d.detail}</div>
            {d.args && <div className="small mono muted">{JSON.stringify(d.args).slice(0, 300)}</div>}
          </div>
        ))}
        <div className="small muted" style={{ marginTop: 8 }}>
          The LLM (when configured) only chooses among candidates generated from the current gaps; it cannot invent tools or arguments. Rules: hard budgets (steps, events/query, time window, graph nodes, LLM/TI calls), stop when sufficiency ≥ τ with no open critical gap, or on diminishing returns.
        </div>
      </div>
    </div>
  )
}

function EvidenceTab({ id, st, focus }) {
  const [open, setOpen] = useState(focus)
  const [records, setRecords] = useState({})
  const ev = st.evidence || []
  const toggle = (evd) => {
    if (open === evd) return setOpen(null)
    setOpen(evd)
    if (!records[evd]) api.evidenceRecords(id, evd, 50).then((r) => setRecords((m) => ({ ...m, [evd]: r })))
  }
  useEffect(() => {
    if (focus) toggle(focus)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [focus])
  return (
    <div className="card">
      <h3>Evidence items ({ev.length}) — each is a recorded tool call; records are fetched from the repository on demand</h3>
      <table>
        <thead>
          <tr>
            <th>id</th>
            <th>step</th>
            <th>tool</th>
            <th>summary</th>
            <th>records</th>
            <th>relevance</th>
            <th>novelty</th>
            <th>ms</th>
          </tr>
        </thead>
        <tbody>
          {ev.map((e) => (
            <React.Fragment key={e.evidence_id}>
              <tr className="clickable" onClick={() => toggle(e.evidence_id)}>
                <td className="mono small">{e.evidence_id.slice(-10)}</td>
                <td>{e.step}</td>
                <td>
                  <code>{e.tool}</code>
                </td>
                <td className="small">{e.summary}</td>
                <td className="small">
                  {e.record_count}/{e.total_matched}
                  {e.truncated ? ' ⚠︎' : ''}
                </td>
                <td>
                  <Badge kind={e.relevance === 'supporting' ? 'ok' : e.relevance === 'empty' ? 'failed' : 'info'}>{e.relevance}</Badge>
                </td>
                <td>{e.novelty}</td>
                <td className="small">{Math.round(e.latency_ms)}</td>
              </tr>
              {open === e.evidence_id && (
                <tr>
                  <td colSpan={8}>
                    <div className="grid cols-2">
                      <div>
                        <div className="muted small">arguments</div>
                        <pre className="pre">{JSON.stringify(e.args, null, 1)}</pre>
                        <div className="muted small">provenance</div>
                        <pre className="pre">{JSON.stringify(e.provenance, null, 1)}</pre>
                        {e.buckets && (
                          <>
                            <div className="muted small">aggregate buckets</div>
                            <pre className="pre">{JSON.stringify(e.buckets, null, 1)}</pre>
                          </>
                        )}
                        {e.ti && (
                          <>
                            <div className="muted small">threat-intel API result</div>
                            <pre className="pre">{JSON.stringify(e.ti, null, 1)}</pre>
                          </>
                        )}
                        {e.mappings && (
                          <>
                            <div className="muted small">MITRE mappings</div>
                            <pre className="pre">{JSON.stringify(e.mappings.map((m) => ({ attack_type: m.attack_type, technique_id: m.technique_id, name: m.name, confidence: m.confidence })), null, 1)}</pre>
                          </>
                        )}
                      </div>
                      <div>
                        <div className="muted small">records ({e.record_ids?.length || 0} ids retained)</div>
                        {records[e.evidence_id] ? (
                          <div className="table-wrap" style={{ maxHeight: 360, overflow: 'auto' }}>
                            <table>
                              <thead>
                                <tr>
                                  <th>id</th>
                                  <th>time</th>
                                  <th>src → dst</th>
                                  <th>prediction</th>
                                </tr>
                              </thead>
                              <tbody>
                                {records[e.evidence_id].events.map((r) => (
                                  <tr key={r._id}>
                                    <td className="mono small">
                                      <Link to={`/events?id=${r._id}`}>{r._id.slice(-8)}</Link>
                                    </td>
                                    <td className="small">{fmtTime(r.timestamp)}</td>
                                    <td className="mono small">
                                      {r.source_ip}→{r.destination_ip}
                                    </td>
                                    <td className="small">
                                      {r.prediction?.attack_type} {(r.prediction?.confidence ?? 0).toFixed(2)}
                                    </td>
                                  </tr>
                                ))}
                                {records[e.evidence_id].alerts.map((r) => (
                                  <tr key={r._id}>
                                    <td className="mono small">
                                      <Link to={`/alerts/${r._id}`}>{r._id.slice(-8)}</Link>
                                    </td>
                                    <td className="small">{fmtTime(r.first_seen)}</td>
                                    <td className="mono small">{r.source_ip}</td>
                                    <td className="small">
                                      alert: {r.attack_type} <Severity level={r.severity} />
                                    </td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        ) : (
                          <div className="muted small">loading…</div>
                        )}
                      </div>
                    </div>
                  </td>
                </tr>
              )}
            </React.Fragment>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export function ChainTab({ st, id }) {
  const chain = st.attack_chain
  if (!chain) return <div className="card muted">Attack chain is produced when the evidence loop terminates.</div>
  return (
    <div className="grid cols-2">
      <div className="card">
        <h3>Reconstructed chain ({chain.stage_count} stages)</h3>
        <div className="stage-list">
          {chain.stages.map((s, i) => (
            <React.Fragment key={s.stage}>
              {i > 0 && <span className="arrow">→</span>}
              <div className={`stage ${s.support}`}>
                <div className="n">
                  stage {s.stage} · {s.support} support{s.is_alert_stage ? ' · alert' : ''}
                </div>
                <b>{s.attack_type}</b>
                <div className="small muted">{s.event_count} flows</div>
                <div className="small muted">{fmtTime(s.first_seen).slice(11)}</div>
              </div>
            </React.Fragment>
          ))}
        </div>
        <div className="small muted" style={{ marginTop: 10 }}>{chain.method}</div>
        <h3 style={{ marginTop: 14 }}>Stage links</h3>
        <table>
          <thead>
            <tr>
              <th>from → to</th>
              <th>gap / overlap (s)</th>
              <th>link</th>
              <th>shared targets</th>
            </tr>
          </thead>
          <tbody>
            {chain.relationships.map((r, i) => (
              <tr key={i}>
                <td>
                  {r.from_stage} → {r.to_stage}
                </td>
                <td>{r.temporal_relation === 'overlapping' ? <span title="stages overlap in time; ordered by first-seen">overlap {Math.round(r.overlap_seconds)}</span> : r.gap_seconds === null || r.gap_seconds === undefined ? '—' : Math.round(r.gap_seconds)}</td>
                <td>
                  <Badge kind={r.link_strength === 'strong' ? 'ok' : r.link_strength === 'moderate' ? 'medium' : 'failed'}>{r.link_strength}</Badge>
                </td>
                <td className="small mono">{r.shared_targets.join(', ') || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {chain.unsupported_gaps?.length > 0 && (
          <div className="banner warn" style={{ marginTop: 10 }}>
            ⚠️
            <ul style={{ margin: 0, paddingLeft: 16 }}>
              {chain.unsupported_gaps.map((g, i) => (
                <li key={i}>{g}</li>
              ))}
            </ul>
          </div>
        )}
        {chain.distributed_sources?.length > 0 && (
          <>
            <h3 style={{ marginTop: 14 }}>Distributed sources (same target, same window)</h3>
            <table>
              <tbody>
                {chain.distributed_sources.map((d) => (
                  <tr key={d.source_ip}>
                    <td className="mono">{d.source_ip}</td>
                    <td className="small">{Array.from(new Set(d.attack_types)).join(', ')}</td>
                    <td>{d.event_count} flows</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}
      </div>
      <div className="card">
        <h3>Timeline</h3>
        <div className="timeline">
          {chain.timeline.map((t, i) => (
            <div key={i} className={`tl-item ${t.type}`}>
              <div className="small muted">{fmtTime(t.time)}</div>
              <div>{t.title}</div>
              {t.evidence_ids?.length > 0 && (
                <div className="small">
                  <EvidenceIds ids={t.evidence_ids} invId={id} max={3} />
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
