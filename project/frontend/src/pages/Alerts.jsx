// import React, { useState } from 'react'
// import { useNavigate } from 'react-router-dom'
// import { api } from '../services/api'
// import { Badge, ErrorBox, Loading, Pager, Severity, fmtTime, useAsync } from '../components/common'

// export default function Alerts() {
//   const nav = useNavigate()
//   const [page, setPage] = useState(1)
//   const [f, setF] = useState({ severity: '', category: '', status: '', q: '' })
//   const params = { page, page_size: 25, ...Object.fromEntries(Object.entries(f).filter(([, v]) => v)) }
//   const { loading, data, error } = useAsync(() => api.alerts(params), [page, f.severity, f.category, f.status, f.q])
//   const summary = useAsync(() => api.alertsSummary(), [])
//   const cats = (summary.data?.by_category || []).map((r) => r._id)

//   return (
//     <div>
//       <div className="page-title">
//         <h1>Alerts</h1>
//         <span className="sub">{data ? `${data.total} alerts` : ''}</span>
//       </div>
//       <div className="card" style={{ marginBottom: 12 }}>
//         <div className="row">
//           <select value={f.severity} onChange={(e) => { setPage(1); setF({ ...f, severity: e.target.value }) }}>
//             <option value="">all severities</option>
//             {['critical', 'high', 'medium', 'low', 'info'].map((s) => (
//               <option key={s}>{s}</option>
//             ))}
//           </select>
//           <select value={f.category} onChange={(e) => { setPage(1); setF({ ...f, category: e.target.value }) }}>
//             <option value="">all categories</option>
//             {cats.map((c) => (
//               <option key={c}>{c}</option>
//             ))}
//           </select>
//           <select value={f.status} onChange={(e) => { setPage(1); setF({ ...f, status: e.target.value }) }}>
//             <option value="">all statuses</option>
//             {['open', 'investigating', 'resolved', 'false_positive', 'closed'].map((s) => (
//               <option key={s}>{s}</option>
//             ))}
//           </select>
//           <input placeholder="search ip / type / id" value={f.q} onChange={(e) => { setPage(1); setF({ ...f, q: e.target.value }) }} style={{ minWidth: 220 }} />
//         </div>
//       </div>
//       <ErrorBox error={error} />
//       {loading ? (
//         <Loading />
//       ) : (
//         <div className="card table-wrap">
//           <table>
//             <thead>
//               <tr>
//                 <th>severity</th>
//                 <th>attack type</th>
//                 <th>category</th>
//                 <th>source</th>
//                 <th>targets</th>
//                 <th>flows</th>
//                 <th>conf</th>
//                 <th>first seen</th>
//                 <th>status</th>
//                 <th>investigations</th>
//               </tr>
//             </thead>
//             <tbody>
//               {data.items.map((a) => (
//                 <tr key={a._id} className="clickable" onClick={() => nav(`/alerts/${a._id}`)}>
//                   <td>
//                     <Severity level={a.severity} />
//                   </td>
//                   <td>{a.attack_type}</td>
//                   <td className="small">{a.category}</td>
//                   <td className="mono">{a.source_ip}</td>
//                   <td className="mono small">
//                     {(a.destination_ips || []).slice(0, 2).join(', ')}
//                     {a.destination_ips?.length > 2 ? ` +${a.destination_ips.length - 2}` : ''}
//                   </td>
//                   <td>{a.event_count}</td>
//                   <td>{(a.confidence_mean ?? 0).toFixed(2)}</td>
//                   <td className="small">{fmtTime(a.first_seen)}</td>
//                   <td>
//                     <Badge kind={a.status}>{a.status}</Badge>
//                   </td>
//                   <td>{a.investigation_ids?.length || 0}</td>
//                 </tr>
//               ))}
//             </tbody>
//           </table>
//           <Pager page={page} pageSize={25} total={data.total} onChange={setPage} />
//         </div>
//       )}
//     </div>
//   )
// }


import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../services/api'
import {
  Badge,
  ErrorBox,
  Loading,
  Pager,
  Severity,
  fmtTime,
  useAsync,
} from '../components/common'

function confidenceLabel(value) {
  if (value == null) return '—'

  if (value >= 0.8) return 'High'
  if (value >= 0.5) return 'Medium'
  return 'Low'
}

export default function Alerts() {
  const nav = useNavigate()
  const [page, setPage] = useState(1)

  const [f, setF] = useState({
    severity: '',
    category: '',
    status: '',
    q: '',
  })

  const params = {
    page,
    page_size: 25,
    ...Object.fromEntries(
      Object.entries(f).filter(([, v]) => v)
    ),
  }

  const { loading, data, error } = useAsync(
    () => api.alerts(params),
    [page, f.severity, f.category, f.status, f.q]
  )

  const summary = useAsync(() => api.alertsSummary(), [])

  const cats = (summary.data?.by_category || []).map(
    (r) => r._id
  )

  return (
    <div>
      <div className="page-title">
        <h1>Alerts</h1>

        <span className="sub">
          {data ? `${data.total} security alerts` : ''}
        </span>
      </div>

      <div className="card" style={{ marginBottom: 12 }}>
        <div className="row">

          <select
            value={f.severity}
            onChange={(e) => {
              setPage(1)
              setF({
                ...f,
                severity: e.target.value,
              })
            }}
          >
            <option value="">All severities</option>

            {[
              'critical',
              'high',
              'medium',
              'low',
              'info',
            ].map((s) => (
              <option key={s} value={s}>
                {s.charAt(0).toUpperCase() + s.slice(1)}
              </option>
            ))}
          </select>

          <select
            value={f.category}
            onChange={(e) => {
              setPage(1)
              setF({
                ...f,
                category: e.target.value,
              })
            }}
          >
            <option value="">All categories</option>

            {cats.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>

          <select
            value={f.status}
            onChange={(e) => {
              setPage(1)
              setF({
                ...f,
                status: e.target.value,
              })
            }}
          >
            <option value="">All statuses</option>

            {[
              'open',
              'investigating',
              'resolved',
              'false_positive',
              'closed',
            ].map((s) => (
              <option key={s} value={s}>
                {s.replace('_', ' ')}
              </option>
            ))}
          </select>

          <input
            placeholder="Search alerts..."
            value={f.q}
            onChange={(e) => {
              setPage(1)
              setF({
                ...f,
                q: e.target.value,
              })
            }}
            style={{ minWidth: 220 }}
          />

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
                <th>Severity</th>
                <th>Threat</th>
                <th>Category</th>
                <th>Source</th>
                <th>Targets</th>
                <th>Events</th>
                <th>Confidence</th>
                <th>First Seen</th>
                <th>Status</th>
                <th>Investigations</th>
              </tr>
            </thead>

            <tbody>
              {(data?.items || []).map((a) => (
                <tr
                  key={a._id}
                  className="clickable"
                  onClick={() =>
                    nav(`/alerts/${a._id}`)
                  }
                >
                  <td>
                    <Severity level={a.severity} />
                  </td>

                  <td>
                    <b>{a.attack_type}</b>
                  </td>

                  <td className="small">
                    {a.category || '—'}
                  </td>

                  <td className="mono">
                    {a.source_ip || '—'}
                  </td>

                  <td className="mono small">
                    {(a.destination_ips || [])
                      .slice(0, 2)
                      .join(', ')}

                    {a.destination_ips?.length > 2
                      ? ` +${a.destination_ips.length - 2}`
                      : ''}
                  </td>

                  <td>
                    {a.event_count ?? 0}
                  </td>

                  <td>
                    <Badge>
                      {confidenceLabel(a.confidence_mean)}
                    </Badge>
                  </td>

                  <td className="small">
                    {fmtTime(a.first_seen)}
                  </td>

                  <td>
                    <Badge kind={a.status}>
                      {a.status
                        ? a.status.replace('_', ' ')
                        : 'unknown'}
                    </Badge>
                  </td>

                  <td>
                    {a.investigation_ids?.length || 0}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {!data?.items?.length && (
            <div
              className="muted small"
              style={{
                padding: 20,
                textAlign: 'center',
              }}
            >
              No alerts found.
            </div>
          )}

          <Pager
            page={page}
            pageSize={25}
            total={data?.total || 0}
            onChange={setPage}
          />
        </div>
      )}
    </div>
  )
}