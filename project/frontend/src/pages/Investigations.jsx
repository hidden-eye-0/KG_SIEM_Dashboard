// import React, { useState } from 'react'
// import { useNavigate } from 'react-router-dom'
// import { api } from '../services/api'
// import { Badge, ErrorBox, Loading, Pager, fmtTime, useAsync } from '../components/common'

// export default function Investigations() {
//   const nav = useNavigate()
//   const [page, setPage] = useState(1)
//   const [mode, setMode] = useState('')
//   const { loading, data, error } = useAsync(() => api.investigations({ page, page_size: 25, mode: mode || undefined }), [page, mode])
//   return (
//     <div>
//       <div className="page-title">
//         <h1>Investigations</h1>
//         <span className="sub">{data ? `${data.total} total` : ''}</span>
//       </div>
//       <div className="banner info">
//         ℹ️ <div>
//           <b>Adaptive</b> investigations choose each next query from the current state (open evidence gaps, hypothesis, graph). <b>Baseline</b> runs the same graph/report code with a fixed
//           3-query plan and exists only for comparison. Open an alert to start either.
//         </div>
//       </div>
//       <div className="row" style={{ marginBottom: 10 }}>
//         <select value={mode} onChange={(e) => { setPage(1); setMode(e.target.value) }}>
//           <option value="">all modes</option>
//           <option value="adaptive">adaptive</option>
//           <option value="baseline">baseline</option>
//         </select>
//       </div>
//       <ErrorBox error={error} />
//       {loading ? (
//         <Loading />
//       ) : (
//         <div className="card table-wrap">
//           <table>
//             <thead>
//               <tr>
//                 <th>id</th>
//                 <th>alert</th>
//                 <th>mode / policy</th>
//                 <th>status</th>
//                 <th>steps</th>
//                 <th>queries</th>
//                 <th>events</th>
//                 <th>LLM calls</th>
//                 <th>graph</th>
//                 <th>chain</th>
//                 <th>stop reason</th>
//                 <th>created</th>
//               </tr>
//             </thead>
//             <tbody>
//               {data.items.map((i) => (
//                 <tr key={i._id} className="clickable" onClick={() => nav(`/investigations/${i._id}`)}>
//                   <td className="mono small">{i._id.slice(-12)}</td>
//                   <td className="small">
//                     {i.alert_summary?.attack_type} <span className="muted mono">{i.alert_summary?.source_ip}</span>
//                   </td>
//                   <td>
//                     <Badge>{i.mode}</Badge> <span className="small muted">{i.policy}</span>
//                   </td>
//                   <td>
//                     <Badge kind={i.status}>{i.status}</Badge>
//                   </td>
//                   <td>{i.metrics?.steps ?? '—'}</td>
//                   <td>{i.metrics?.db_queries ?? '—'}</td>
//                   <td>{i.metrics?.events_retrieved ?? '—'}</td>
//                   <td>{i.metrics?.llm_calls ?? '—'}</td>
//                   <td className="small">
//                     {i.metrics?.graph_nodes ?? '—'}n / {i.metrics?.graph_edges ?? '—'}e
//                   </td>
//                   <td>{i.metrics?.stage_count ?? '—'}</td>
//                   <td className="small">{i.metrics?.termination_reason || '—'}</td>
//                   <td className="small">{fmtTime(i.created_at)}</td>
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
import { Badge, ErrorBox, Loading, Pager, fmtTime, useAsync } from '../components/common'

export default function Investigations() {
  const nav = useNavigate()
  const [page, setPage] = useState(1)
  const [status, setStatus] = useState('')

  const { loading, data, error } = useAsync(
    () =>
      api.investigations({
        page,
        page_size: 25,
        status: status || undefined,
      }),
    [page, status]
  )

  return (
    <div>
      <div className="page-title">
        <h1>Investigations</h1>
        <span className="sub">
          {data ? `${data.total} investigations` : ''}
        </span>
      </div>

      <div className="banner info">
        <div>
          <b>Security investigations</b>
          <div className="small muted" style={{ marginTop: 4 }}>
            Review alerts, supporting evidence, and investigation findings.
          </div>
        </div>
      </div>

      <div className="row" style={{ marginBottom: 10 }}>
        <select
          value={status}
          onChange={(e) => {
            setPage(1)
            setStatus(e.target.value)
          }}
        >
          <option value="">All statuses</option>
          <option value="running">Running</option>
          <option value="completed">Completed</option>
          <option value="failed">Failed</option>
        </select>
      </div>

      <ErrorBox error={error} />

      {loading ? (
        <Loading />
      ) : (
        <div className="card table-wrap">
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Alert</th>
                <th>Status</th>
                <th>Steps</th>
                <th>Events</th>
                <th>Progress</th>
                <th>Created</th>
              </tr>
            </thead>

            <tbody>
              {(data?.items || []).map((i) => (
                <tr
                  key={i._id}
                  className="clickable"
                  onClick={() => nav(`/investigations/${i._id}`)}
                >
                  <td className="mono small">
                    {i._id.slice(-12)}
                  </td>

                  <td className="small">
                    <div>
                      {i.alert_summary?.attack_type || 'Security Alert'}
                    </div>

                    {i.alert_summary?.source_ip && (
                      <span className="muted mono">
                        {i.alert_summary.source_ip}
                      </span>
                    )}
                  </td>

                  <td>
                    <Badge kind={i.status}>
                      {i.status || 'unknown'}
                    </Badge>
                  </td>

                  <td>
                    {i.metrics?.steps ?? '—'}
                  </td>

                  <td>
                    {i.metrics?.events_retrieved ?? '—'}
                  </td>

                  <td>
                    {i.metrics?.stage_count
                      ? `${i.metrics.stage_count} stages`
                      : '—'}
                  </td>

                  <td className="small">
                    {fmtTime(i.created_at)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {!data?.items?.length && (
            <div
              className="muted small"
              style={{ padding: 20, textAlign: 'center' }}
            >
              No investigations found.
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