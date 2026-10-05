import React, { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { api } from '../services/api'
import { Badge, ErrorBox, KV, Loading, Pager, ProvenanceBanner, fmtTime, useAsync } from '../components/common'

export default function Events() {
  const [sp] = useSearchParams()
  const focusId = sp.get('id')
  const [page, setPage] = useState(1)
  const [f, setF] = useState({ source_ip: '', destination_ip: '', device_id: '', attack_type: '', category: '' })
  const [detail, setDetail] = useState(null)
  const params = { page, page_size: 50, ...Object.fromEntries(Object.entries(f).filter(([, v]) => v)) }
  const { loading, data, error } = useAsync(() => api.events(params), [page, JSON.stringify(f)])
  const summary = useAsync(() => api.eventsSummary(), [])

  useEffect(() => {
    if (focusId) api.event(focusId).then(setDetail).catch(() => {})
  }, [focusId])

  const types = (summary.data?.by_attack_type || []).map((r) => r._id).filter(Boolean)
  return (
    <div>
      <div className="page-title">
        <h1>Security events</h1>
        <span className="sub">{data ? `${data.total.toLocaleString()} events` : ''} · paginated; features are stored per event, ground truth is never exposed</span>
      </div>
      <ProvenanceBanner dataSource={summary.data?.data_source} provenance={summary.data?.provenance} compact />
      {detail && (
        <div className="card" style={{ marginBottom: 12 }}>
          <div className="row">
            <h3 style={{ margin: 0 }}>
              Event <span className="mono">{detail._id}</span>
            </h3>
            <span className="spacer" />
            <button className="secondary" onClick={() => setDetail(null)}>
              close
            </button>
          </div>
          <div className="grid cols-3" style={{ marginTop: 8 }}>
            <KV data={{ timestamp: fmtTime(detail.timestamp), source_ip: detail.source_ip, destination_ip: detail.destination_ip, device: `${detail.device_id} (${detail.device_type})`, protocol: detail.protocol, log_source: detail.log_source }} />
            <KV data={{ ...detail.prediction, provenance: detail.context?.provenance, scenario_name: detail.context?.scenario_name, data_source: detail.dataset?.source }} />
            <div>
              <div className="muted small">features (46)</div>
              <pre className="pre" style={{ maxHeight: 200 }}>
                {JSON.stringify(detail.features, null, 0)}
              </pre>
            </div>
          </div>
        </div>
      )}
      <div className="card" style={{ marginBottom: 12 }}>
        <div className="row">
          {['source_ip', 'destination_ip', 'device_id'].map((k) => (
            <input key={k} placeholder={k} value={f[k]} onChange={(e) => { setPage(1); setF({ ...f, [k]: e.target.value }) }} />
          ))}
          <select value={f.attack_type} onChange={(e) => { setPage(1); setF({ ...f, attack_type: e.target.value }) }}>
            <option value="">all predicted types</option>
            {types.map((t) => (
              <option key={t}>{t}</option>
            ))}
          </select>
        </div>
      </div>
      <ErrorBox error={error} />
      {loading ? (
        <Loading />
      ) : (
        <div className="card table-wrap">
          <table>
            <thead>
              <tr>
                <th>id</th>
                <th>time</th>
                <th>source</th>
                <th>destination</th>
                <th>device</th>
                <th>proto</th>
                <th>prediction</th>
                <th>conf</th>
                <th>prov</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((e) => (
                <tr key={e._id} className="clickable" onClick={() => setDetail(e)}>
                  <td className="mono small">{e._id.slice(-10)}</td>
                  <td className="small">{fmtTime(e.timestamp)}</td>
                  <td className="mono small">{e.source_ip}</td>
                  <td className="mono small">{e.destination_ip}</td>
                  <td className="small">{e.device_id}</td>
                  <td className="small">{e.protocol}</td>
                  <td className="small">
                    {e.prediction?.attack_type} <span className="muted">{e.prediction?.category}</span>
                  </td>
                  <td className="small">{(e.prediction?.confidence ?? 0).toFixed(2)}</td>
                  <td>
                    <Badge kind="synth">{e.context?.provenance}</Badge>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <Pager page={page} pageSize={50} total={data.total} onChange={setPage} />
        </div>
      )}
    </div>
  )
}
