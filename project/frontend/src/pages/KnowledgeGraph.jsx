import React from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { api } from '../services/api'
import { Badge, Loading, useAsync } from '../components/common'
import GraphView, { NODE_COLORS } from '../components/GraphView'

export default function KnowledgeGraph() {
  const { id } = useParams()
  const nav = useNavigate()
  const invs = useAsync(() => api.investigations({ page_size: 100 }), [])
  const items = (invs.data?.items || []).filter((i) => i.status === 'completed' || i.status === 'running')
  const current = id || items[0]?._id
  const summary = useAsync(() => (current ? api.graph(current, { limit: 1 }).then((g) => g.summary) : null), [current])

  return (
    <div>
      <div className="page-title">
        <h1>Knowledge graph</h1>
        <span className="sub">deterministically derived from evidence (rules R1–R7); the LLM never writes to it</span>
      </div>
      <div className="row" style={{ marginBottom: 10 }}>
        <label className="muted small">investigation</label>
        <select value={current || ''} onChange={(e) => nav(`/graph/${e.target.value}`)} style={{ minWidth: 420 }}>
          {items.map((i) => (
            <option key={i._id} value={i._id}>
              {i._id.slice(-12)} · {i.mode} · {i.alert_summary?.attack_type} from {i.alert_summary?.source_ip} · {i.status}
            </option>
          ))}
        </select>
        {summary.data && (
          <span className="small muted">
            {Object.entries(summary.data.by_type || {}).map(([t, n]) => (
              <span key={t} style={{ marginRight: 8 }}>
                <span style={{ color: NODE_COLORS[t] }}>●</span> {t} {n}
              </span>
            ))}
          </span>
        )}
      </div>
      {invs.loading ? (
        <Loading />
      ) : !current ? (
        <div className="card muted">No investigations yet — start one from an alert.</div>
      ) : (
        <div className="card">
          <GraphView invId={current} height={700} hideTypes={[]} />
          <div className="small muted" style={{ marginTop: 8 }}>
            Derivation rules: <Badge>R1</Badge> COMMUNICATES_WITH from flows · <Badge>R2</Badge> PERFORMS/TARGETS/GENERATES from predicted attack clusters and alerts · <Badge>R3</Badge> SUPPORTED_BY evidence sets · <Badge>R4</Badge> Behavior INDICATES · <Badge>R5</Badge> IOC ASSOCIATED_WITH (actual TI results only) · <Badge>R6</Badge> MAPS_TO ATT&CK (curated, class-level) · <Badge>R7</Badge> OCCURS_BEFORE between attacks of the same source.
          </div>
        </div>
      )}
    </div>
  )
}
