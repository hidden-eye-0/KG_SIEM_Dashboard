import axios from 'axios'

// All calls are relative (/api/...) — the Vite dev server (or FastAPI in production) proxies/serves them.
// No secrets live in the frontend: API keys stay in the backend .env.
const http = axios.create({ baseURL: '/api', timeout: 60000 })

http.interceptors.request.use((cfg) => {
  const token = localStorage.getItem('token')
  if (token) cfg.headers.Authorization = `Bearer ${token}`
  return cfg
})

http.interceptors.response.use(
  (r) => r.data,
  (err) => {
    const detail = err?.response?.data?.detail || err.message
    return Promise.reject(new Error(typeof detail === 'string' ? detail : JSON.stringify(detail)))
  },
)

export const api = {
  health: () => http.get('/health'),
  config: () => http.get('/config'),
  login: (username, password) => http.post('/auth/login', { username, password }),
  me: () => http.get('/auth/me'),

  datasetStatus: () => http.get('/dataset/status'),
  datasetInspection: () => http.get('/dataset/inspection'),
  scenarios: () => http.get('/dataset/scenarios'),
  reseed: (fast = true) => http.post(`/dataset/reseed?fast=${fast}`),

  models: () => http.get('/models'),
  model: (v) => http.get(`/models/${v}`),
  profiles: () => http.get('/profiles'),
  globalProfile: () => http.get('/profiles/global'),
  profile: (id) => http.get(`/profiles/${encodeURIComponent(id)}`),

  events: (params) => http.get('/events', { params }),
  eventsSummary: () => http.get('/events/summary'),
  eventsTimeline: (params) => http.get('/events/timeline', { params }),
  event: (id) => http.get(`/events/${id}`),
  eventsBatch: (ids) => http.post('/events/batch', { ids }),

  alerts: (params) => http.get('/alerts', { params }),
  alertsSummary: () => http.get('/alerts/summary'),
  alert: (id) => http.get(`/alerts/${id}`),
  alertEvents: (id, limit = 100) => http.get(`/alerts/${id}/events`, { params: { limit } }),
  setAlertStatus: (id, status) => http.post(`/alerts/${id}/status`, { status }),

  investigations: (params) => http.get('/investigations', { params }),
  createInvestigation: (body) => http.post('/investigations', body),
  investigation: (id, includeState = true) => http.get(`/investigations/${id}`, { params: { include_state: includeState } }),
  steps: (id) => http.get(`/investigations/${id}/steps`),
  evidence: (id) => http.get(`/investigations/${id}/evidence`),
  evidenceRecords: (id, evd, limit = 100) => http.get(`/investigations/${id}/evidence/${evd}/records`, { params: { limit } }),
  stopInvestigation: (id) => http.post(`/investigations/${id}/stop`),

  graph: (id, params) => http.get(`/graph/${id}`, { params }),
  node: (id, key, records = 50) => http.get(`/graph/${id}/node`, { params: { key, records } }),

  reports: (params) => http.get('/reports', { params }),
  report: (id) => http.get(`/reports/${id}`),
  reportMarkdown: (id) => http.get(`/reports/${id}/markdown`, { responseType: 'text' }),

  ti: () => http.get('/threat-intel'),
  tiLookup: (indicator, provider = 'all') => http.get('/threat-intel/lookup', { params: { indicator, provider } }),
  tiInterpret: (indicator, provider) => http.post('/threat-intel/interpret', { indicator, provider }),
  mitre: () => http.get('/mitre/techniques'),

  runEvaluation: (body) => http.post('/evaluation/run', body),
  evalJob: (id) => http.get(`/evaluation/jobs/${id}`),
  evalRuns: () => http.get('/evaluation/runs'),
  evalRun: (id) => http.get(`/evaluation/runs/${id}`),
  score: (id) => http.get(`/evaluation/score/${id}`),
  grounding: (id) => http.get(`/evaluation/grounding/${id}`),
}

/** Server-sent events for a running investigation. Returns a close() function. */
export function streamInvestigation(id, handlers) {
  const es = new EventSource(`/api/investigations/${id}/stream`)
  const on = (type) => (e) => {
    try {
      handlers[type]?.(JSON.parse(e.data))
    } catch (err) {
      console.error('bad SSE payload', err)
    }
  }
  es.addEventListener('agent_action', on('agent_action'))
  es.addEventListener('state', on('state'))
  es.addEventListener('done', (e) => {
    on('done')(e)
    es.close()
  })
  es.onerror = () => handlers.error?.()
  return () => es.close()
}
