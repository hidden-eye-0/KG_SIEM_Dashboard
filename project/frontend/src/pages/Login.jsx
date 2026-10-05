import React, { useState } from 'react'
import { useApp } from '../App'

export default function Login({ error }) {
  const { login } = useApp()
  const [u, setU] = useState('analyst')
  const [p, setP] = useState('')
  const [err, setErr] = useState(null)
  const submit = async (e) => {
    e.preventDefault()
    try {
      await login(u, p)
    } catch (ex) {
      setErr(ex)
    }
  }
  return (
    <div className="login card">
      <h2 style={{ marginTop: 0 }}>Analyst sign-in</h2>
      <p className="muted small">AUTH_REQUIRED is enabled on the backend. Use the demo analyst account configured in <code>.env</code>.</p>
      <form onSubmit={submit} className="grid">
        <input placeholder="username" value={u} onChange={(e) => setU(e.target.value)} />
        <input placeholder="password" type="password" value={p} onChange={(e) => setP(e.target.value)} />
        <button type="submit">Sign in</button>
        {(err || error) && <div className="error small">{String((err || error).message)}</div>}
      </form>
    </div>
  )
}
