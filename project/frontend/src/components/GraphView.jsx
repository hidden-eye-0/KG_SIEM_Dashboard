import React, { useEffect, useRef, useState } from 'react'
import cytoscape from 'cytoscape'
import dagre from 'cytoscape-dagre'
import { api } from '../services/api'
import { EvidenceIds, KV, fmtTime } from './common'

cytoscape.use(dagre)

export const NODE_COLORS = {
  Investigation: '#5b6b8c',
  Alert: '#ff5c5c',
  IP: '#4f9cf9',
  Device: '#2ecc71',
  Attack: '#f5b942',
  Behavior: '#b48ef7',
  EvidenceSet: '#7d8aa3',
  IOC: '#ff8c42',
  MITRETechnique: '#e05cff',
  Domain: '#3fc1c9',
  User: '#c9d13f',
  Process: '#8ad',
  File: '#aaa',
}

const EDGE_COLORS = { OCCURS_BEFORE: '#f5b942', PERFORMS: '#ff8c8c', TARGETS: '#ff5c5c', COMMUNICATES_WITH: '#4f9cf9', MAPS_TO: '#e05cff', SUPPORTED_BY: '#7d8aa3', INDICATES: '#b48ef7', ASSOCIATED_WITH: '#ff8c42' }

function labelOf(n) {
  const p = n.properties || {}
  switch (n.label) {
    case 'IP':
      return p.address || n.key.split(':').slice(1).join(':')
    case 'Device':
      return p.device_id || n.key
    case 'Attack':
      return `${p.attack_type || 'Attack'}\n${p.event_count ?? ''} flows`
    case 'Alert':
      return `Alert ${String(p.severity || '').toUpperCase()}`
    case 'EvidenceSet':
      return `Evidence\n${p.tool || ''}`
    case 'MITRETechnique':
      return `${p.technique_id}\n${(p.name || '').slice(0, 22)}`
    case 'IOC':
      return `${p.provider}: ${p.verdict || p.status}`
    case 'Behavior':
      return 'Behavior profile'
    case 'Investigation':
      return 'Investigation'
    default:
      return n.key
  }
}

/**
 * Cytoscape rendering of an investigation subgraph. Clicking a node loads the supporting evidence
 * (records + evidence items) from /api/graph/{inv}/node — nothing is inferred client-side.
 */
export default function GraphView({ invId, refreshKey, height = 620, hideTypes = ['EvidenceSet'] }) {
  const ref = useRef(null)
  const cyRef = useRef(null)
  const [data, setData] = useState(null)
  const [selected, setSelected] = useState(null)
  const [error, setError] = useState(null)
  const [hidden, setHidden] = useState(new Set(hideTypes))
  const [layout, setLayout] = useState('cose')

  useEffect(() => {
    let alive = true
    api
      .graph(invId, { limit: 1500 })
      .then((d) => alive && setData(d))
      .catch((e) => alive && setError(e))
    return () => {
      alive = false
    }
  }, [invId, refreshKey])

  useEffect(() => {
    if (!data || !ref.current) return
    const nodes = data.nodes.filter((n) => !hidden.has(n.label))
    const keys = new Set(nodes.map((n) => n.key))
    const edges = data.edges.filter((e) => keys.has(e.source) && keys.has(e.target))
    const elements = [
      ...nodes.map((n) => ({ data: { id: n.key, label: labelOf(n), type: n.label, color: NODE_COLORS[n.label] || '#888', raw: n } })),
      ...edges.map((e, i) => ({ data: { id: `${e.id || i}`, source: e.source, target: e.target, label: e.type, color: EDGE_COLORS[e.type] || '#3a4a66', raw: e } })),
    ]
    if (cyRef.current) cyRef.current.destroy()
    const cy = cytoscape({
      container: ref.current,
      elements,
      style: [
        { selector: 'node', style: { 'background-color': 'data(color)', label: 'data(label)', color: '#e6edf7', 'font-size': 9, 'text-wrap': 'wrap', 'text-max-width': 90, 'text-valign': 'bottom', 'text-margin-y': 4, width: 26, height: 26, 'border-width': 2, 'border-color': '#0b1220' } },
        { selector: 'node[type = "Attack"]', style: { shape: 'diamond', width: 34, height: 34 } },
        { selector: 'node[type = "Alert"]', style: { shape: 'triangle' } },
        { selector: 'node[type = "Device"]', style: { shape: 'round-rectangle' } },
        { selector: 'node[type = "MITRETechnique"]', style: { shape: 'hexagon' } },
        { selector: 'node:selected', style: { 'border-color': '#fff', 'border-width': 3 } },
        { selector: 'edge', style: { width: 1.4, 'line-color': 'data(color)', 'target-arrow-color': 'data(color)', 'target-arrow-shape': 'triangle', 'curve-style': 'bezier', label: 'data(label)', 'font-size': 7, color: '#93a4c0', 'text-rotation': 'autorotate', 'text-background-color': '#0a101c', 'text-background-opacity': 0.8, 'text-background-padding': 1, 'arrow-scale': 0.7 } },
        { selector: 'edge[label = "OCCURS_BEFORE"]', style: { width: 2.5, 'line-style': 'dashed' } },
      ],
      layout: layout === 'dagre' ? { name: 'dagre', rankDir: 'LR', nodeSep: 30, rankSep: 70 } : { name: 'cose', animate: false, nodeRepulsion: 9000, idealEdgeLength: 90, padding: 20 },
      wheelSensitivity: 0.2,
    })
    cy.on('tap', 'node', (evt) => {
      const key = evt.target.id()
      setSelected({ key, loading: true })
      api
        .node(invId, key, 25)
        .then((d) => setSelected({ key, data: d }))
        .catch((e) => setSelected({ key, error: e }))
    })
    cy.on('tap', 'edge', (evt) => {
      const e = evt.target.data('raw')
      setSelected({ key: `${e.source} —${e.type}→ ${e.target}`, edge: e })
    })
    cyRef.current = cy
    return () => cy.destroy()
  }, [data, hidden, layout, invId])

  const types = data ? Array.from(new Set(data.nodes.map((n) => n.label))) : []

  return (
    <div>
      <div className="row small" style={{ marginBottom: 8 }}>
        <span className="muted">
          {data ? `${data.nodes.length} nodes · ${data.edges.length} edges · backend ${data.backend}` : 'loading graph…'}
        </span>
        <span className="spacer" />
        <label className="muted">layout</label>
        <select value={layout} onChange={(e) => setLayout(e.target.value)}>
          <option value="cose">force (cose)</option>
          <option value="dagre">hierarchical (dagre)</option>
        </select>
        <button className="secondary" onClick={() => cyRef.current?.fit(undefined, 20)}>
          fit
        </button>
      </div>
      <div className="graph-wrap">
        <div>
          <div className="cy" ref={ref} style={{ height }} />
          <div className="legend">
            {types.map((t) => (
              <span key={t} style={{ '--c': NODE_COLORS[t] || '#888', opacity: hidden.has(t) ? 0.4 : 1, cursor: 'pointer' }} onClick={() => setHidden((h) => { const n = new Set(h); n.has(t) ? n.delete(t) : n.add(t); return n })} title="click to toggle">
                {t}
              </span>
            ))}
            {error && <span className="error">{String(error.message)}</span>}
          </div>
        </div>
        <NodePanel selected={selected} invId={invId} />
      </div>
    </div>
  )
}

function NodePanel({ selected, invId }) {
  if (!selected)
    return (
      <div className="card">
        <h3>Node inspector</h3>
        <div className="muted small">Click a node to see the evidence it was derived from. Every node and relationship carries the record ids that support it; nothing is inferred client-side.</div>
      </div>
    )
  if (selected.loading)
    return (
      <div className="card">
        <h3>{selected.key}</h3>
        <div className="muted">loading evidence…</div>
      </div>
    )
  if (selected.error)
    return (
      <div className="card">
        <h3>{selected.key}</h3>
        <div className="error">{String(selected.error.message)}</div>
      </div>
    )
  if (selected.edge) {
    const e = selected.edge
    return (
      <div className="card" style={{ overflow: 'auto', maxHeight: 700 }}>
        <h3>Relationship</h3>
        <div className="mono small" style={{ marginBottom: 8 }}>{selected.key}</div>
        <KV data={{ derived_by: e.derived_by, confidence: e.confidence, evidence_count: e.evidence_count, first_seen: fmtTime(e.first_seen), last_seen: fmtTime(e.last_seen), gap_seconds: e.gap_seconds, rationale: e.rationale }} />
        <div style={{ marginTop: 8 }}>
          <div className="muted small">supporting records</div>
          <EvidenceIds ids={e.evidence_ids || []} invId={invId} max={8} />
        </div>
      </div>
    )
  }
  const d = selected.data
  return (
    <div className="card" style={{ overflow: 'auto', maxHeight: 700 }}>
      <h3>
        {d.label} <span className="muted">node</span>
      </h3>
      <div className="mono small" style={{ marginBottom: 8, wordBreak: 'break-all' }}>{d.key}</div>
      <KV data={d.properties} />
      <div style={{ marginTop: 10 }}>
        <div className="muted small">relationships ({d.relationships.length})</div>
        <ul className="small" style={{ paddingLeft: 16, margin: '4px 0' }}>
          {d.relationships.slice(0, 12).map((r, i) => (
            <li key={i}>
              <b>{r.type}</b> {r.source === d.key ? '→ ' + r.target : '← ' + r.source} <span className="muted">({r.derived_by}, {r.evidence_count ?? r.evidence_ids?.length ?? 0} rec)</span>
            </li>
          ))}
        </ul>
      </div>
      <div style={{ marginTop: 10 }}>
        <div className="muted small">supporting evidence ids ({d.evidence_ids.length})</div>
        <EvidenceIds ids={d.evidence_ids} invId={invId} max={8} />
      </div>
      {d.events?.length > 0 && (
        <div style={{ marginTop: 10 }}>
          <div className="muted small">sample records</div>
          <table>
            <thead>
              <tr>
                <th>time</th>
                <th>src → dst</th>
                <th>prediction</th>
              </tr>
            </thead>
            <tbody>
              {d.events.slice(0, 10).map((e) => (
                <tr key={e._id}>
                  <td className="small">{fmtTime(e.timestamp)}</td>
                  <td className="small mono">
                    {e.source_ip}→{e.destination_ip}
                  </td>
                  <td className="small">
                    {e.prediction?.attack_type} <span className="muted">{(e.prediction?.confidence ?? 0).toFixed(2)}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {d.evidence_items?.length > 0 && (
        <div style={{ marginTop: 10 }}>
          <div className="muted small">evidence items</div>
          {d.evidence_items.map((e) => (
            <div key={e.evidence_id} className="small" style={{ marginBottom: 4 }}>
              <code>{e.evidence_id}</code> {e.tool}: {e.summary}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
