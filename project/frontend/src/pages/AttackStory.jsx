import React, { useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { api } from '../services/api'
import { Badge, ErrorBox, EvidenceIds, KV, Loading, Severity, fmtTime, useAsync } from '../components/common'
import { ChainTab } from './InvestigationDetail'

export default function AttackStory() {
  const { id } = useParams()
  const nav = useNavigate()
  const reports = useAsync(() => api.reports({ page_size: 100 }), [])
  const current = id || reports.data?.items?.[0]?.investigation_id
  const rep = useAsync(() => (current ? api.report(current) : null), [current])
  const inv = useAsync(() => (current ? api.investigation(current, true) : null), [current])
  const grounding = useAsync(() => (current ? api.grounding(current) : null), [current])
  const [showAll, setShowAll] = useState(false)

  if (reports.loading) return <Loading />
  if (!current) return <div className="card muted">No reports yet — run an investigation first.</div>
  if (rep.error) return <ErrorBox error={rep.error} />
  if (!rep.data) return <Loading />
  const r = rep.data
  const s = r.sections
  const narr = s['13_ai_attack_narrative'] || {}
  const sev = s['3_severity'] || {}
  const ti = s['10_threat_intelligence'] || {}

  return (
    <div>
      <div className="page-title">
        <h1>Attack story & report</h1>
        <span className="sub row">
          <select value={current} onChange={(e) => nav(`/story/${e.target.value}`)} style={{ minWidth: 360 }}>
            {(reports.data.items || []).map((x) => (
              // <option key={x._id} value={x.investigation_id}>
              //   {x.investigation_id.slice(-12)} · {x.analyst_summary?.slice(0, 60)}
              // </option>
              <option key={x._id} value={x.investigation_id}>
                {x.analyst_summary?.slice(0, 70) || 'Security Investigation'}
              </option>
            ))}
          </select>
          <a className="btn secondary" href={`/api/reports/${current}/markdown`} target="_blank" rel="noreferrer">
            Markdown
          </a>
          <a className="btn secondary" href={`/api/reports/${current}/pdf`} target="_blank" rel="noreferrer">
            PDF
          </a>
          <Link className="btn secondary" to={`/investigations/${current}`}>
            investigation
          </Link>
        </span>
      </div>

      <div className="card" style={{ marginBottom: 12 }}>
        <div className="row">
          <Severity level={sev.level} />
          <h2 style={{ margin: 0, fontSize: 18 }}>{s['1_incident_title']}</h2>
        </div>
        {/* <div className="small muted" style={{ marginTop: 4 }}>
          investigation {r.investigation_id} · alert <Link to={`/alerts/${r.alert_id}`}>{r.alert_id}</Link> · generated {fmtTime(r.generated_at)} · stop reason {r.termination_reason}
        </div> */}
        <div className="small muted" style={{ marginTop: 4 }}>
          Related alert{' '}
          <Link to={`/alerts/${r.alert_id}`}>
            {r.alert_id}
          </Link>
          {' · '}
          Report generated {fmtTime(r.generated_at)}
        </div>
        <div style={{ marginTop: 8 }}>{r.analyst_summary}</div>
        <div className="small" style={{ marginTop: 6 }}>
          <b>Severity rationale:</b> {(sev.rationale || []).join(' · ')}
        </div>
      </div>

      <div className="grid cols-2">
        <div className="card">
          {/* <h3>
            AI attack narrative{' '}
            {r.llm?.used ? <Badge kind="llm">Gemini · {narr.model}</Badge> : <Badge>template narrative (LLM unavailable or failed grounding)</Badge>}
          </h3> */}
          <h3>Incident Summary</h3>
          <div className="narrative">{narr.text}</div>
          {/* <div className="small muted" style={{ marginTop: 10 }}>
            Grounding validation: {narr.grounding_validation?.checked ? (narr.grounding_validation.passed ? '✅ passed' : '❌ failed') : 'n/a'} · cited evidence {narr.grounding_validation?.cited_evidence ?? '—'} · unknown ids {narr.grounding_validation?.unknown_evidence_ids?.length ?? 0} · unknown IPs {narr.grounding_validation?.unknown_ips?.length ?? 0} · forbidden phrases {narr.grounding_validation?.forbidden_phrases?.length ?? 0}
          </div> */}
          <div className="small muted" style={{ marginTop: 10 }}>
            Summary generated from the evidence collected during this investigation.
          </div>
        </div>
        <div className="card">
          {/* <h3>
            Evidence-backed claims ({r.metrics?.claims_validated}/{r.metrics?.claims} linked)
          </h3> */}
          <h3>Key Findings</h3>
          {(r.claims || []).slice(0, showAll ? 999 : 8).map((c, i) => (
            <div key={i} className="claim">
              <div>
                {c.validated ? '✅' : '⚠️'} {c.text}
              </div>
              <div className="ev">
                <EvidenceIds ids={c.evidence_ids} invId={current} max={4} />
              </div>
            </div>
          ))}
          {(r.claims || []).length > 8 && (
            <button className="secondary" onClick={() => setShowAll(!showAll)}>
              {showAll ? 'show fewer' : `show all ${r.claims.length}`}
            </button>
          )}
          {/* {grounding.data && (
            <div className="small muted" style={{ marginTop: 8 }}>
              Traceability check: {grounding.data.claims_fully_resolved}/{grounding.data.claims_total} claims resolve to existing evidence/records in the repository.
            </div>
          )} */}
        </div>
      </div>

      {inv.data?.state && (
        <div style={{ marginTop: 14 }}>
          <ChainTab st={inv.data.state} id={current} />
        </div>
      )}

      <div className="grid cols-3" style={{ marginTop: 14 }}>
        <div className="card">
          {/* <h3>Threat intelligence — actual API results</h3> */}
          <h3>Threat Intelligence</h3>
          {ti.results?.length ? (
            ti.results.map((t, i) => (
              // <div key={i} className="claim">
              //   <b>{t.provider}</b> <span className="mono">{t.indicator}</span> <Badge kind={t.status === 'ok' ? 'ok' : 'info'}>{t.status}</Badge>
              //   <div className="small muted">{t.note || JSON.stringify(t.normalized)}</div>
              // </div>
              <div key={i} className="claim">
                <div>
                  <b>{t.indicator}</b>{' '}
                  <Badge kind={t.status === 'ok' ? 'ok' : 'info'}>
                    {t.status}
                  </Badge>
                </div>

                <div className="small muted">
                  {t.note || 'Threat intelligence information available for this indicator.'}
                </div>
              </div>
            ))
          ) : (
            <div className="muted small">Insufficient evidence — no external reputation data was obtained (providers not configured, or indicator in a private/documentation range).</div>
          )}
        </div>
        <div className="card">
          <h3>MITRE ATT&CK (curated class-level associations)</h3>
          {(s['11_mitre_mapping'] || []).map((m, i) => (
            <div key={i} className="small" style={{ marginBottom: 6 }}>
              {m.attack_type} ↔{' '}
              <a href={m.url} target="_blank" rel="noreferrer">
                {m.technique_id}
              </a>{' '}
              {m.name} <Badge kind={m.confidence === 'high' ? 'ok' : 'info'}>{m.confidence}</Badge>
              {m.verified_against_bundle ? ' ✓ bundle' : ''}
            </div>
          ))}
          {!(s['11_mitre_mapping'] || []).length && <div className="muted small">not mapped in this investigation</div>}
        </div>
        <div className="card">
          <h3>Recommended actions</h3>
          <ul style={{ paddingLeft: 16, margin: 0 }}>
            {(s['14_recommended_actions'] || []).map((a, i) => (
              <li key={i} className="small">
                {a}
              </li>
            ))}
          </ul>
        </div>
      </div>

      <div className="grid cols-2" style={{ marginTop: 14 }}>
        <div className="card">
          <h3>Investigation limitations</h3>
          <ul style={{ paddingLeft: 16, margin: 0 }}>
            {(s['15_investigation_limitations'] || []).map((l, i) => (
              <li key={i} className="small">
                {l}
              </li>
            ))}
          </ul>
        </div>
        <div className="card">
          <h3>Supporting evidence & metrics</h3>
          <table>
            <thead>
              <tr>
                <th>evidence</th>
                <th>tool</th>
                <th>records</th>
              </tr>
            </thead>
            <tbody>
              {(s['12_supporting_evidence'] || []).map((e) => (
                <tr key={e.evidence_id}>
                  <td className="mono small">
                    <Link to={`/investigations/${current}?tab=evidence&evd=${e.evidence_id}`}>{e.evidence_id.slice(-10)}</Link>
                  </td>
                  <td className="small">
                    <code>{e.tool}</code> <span className="muted">{e.summary?.slice(0, 80)}</span>
                  </td>
                  <td className="small">
                    {e.record_count}/{e.total_matched}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <div style={{ marginTop: 8 }}>
            <KV data={r.metrics} />
          </div>
        </div>
      </div>
    </div>
  )
}
