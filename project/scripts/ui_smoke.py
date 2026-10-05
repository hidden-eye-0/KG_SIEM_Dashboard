"""Headless smoke test of every dashboard page: loads each route, records console errors,
failed requests and a screenshot. Usage: python scripts/ui_smoke.py [base_url]"""
import sys, json, time
from pathlib import Path
from playwright.sync_api import sync_playwright

base = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5173"
out = Path("data/reports/ui_smoke"); out.mkdir(parents=True, exist_ok=True)
routes = ["/", "/alerts", "/investigations", "/graph", "/story", "/threat-intel", "/events", "/models", "/evaluation", "/settings"]
results = {}
with sync_playwright() as p:
    b = p.chromium.launch()
    pg = b.new_page(viewport={"width": 1440, "height": 1000})
    errors, failed = [], []
    pg.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    pg.on("pageerror", lambda e: errors.append(f"pageerror: {e}"))
    pg.on("requestfailed", lambda r: failed.append(r.url))
    pg.on("response", lambda r: failed.append(f"{r.status} {r.url}") if r.status >= 400 else None)
    # discover an alert + investigation id through the UI's own API
    alerts = pg.request.get(base + "/api/alerts?page_size=1").json()["items"]
    invs = pg.request.get(base + "/api/investigations?page_size=1").json()["items"]
    if alerts: routes.append(f"/alerts/{alerts[0]['_id']}")
    if invs:
        routes += [f"/investigations/{invs[0]['_id']}", f"/investigations/{invs[0]['_id']}?tab=evidence", f"/investigations/{invs[0]['_id']}?tab=chain", f"/graph/{invs[0]['_id']}", f"/story/{invs[0]['_id']}"]
    for r in routes:
        errors.clear(); failed.clear()
        pg.goto(base + r, wait_until="networkidle", timeout=60000)
        time.sleep(1.5)
        name = r.strip("/").replace("/", "_").replace("?", "_").replace("=", "-") or "dashboard"
        pg.screenshot(path=str(out / f"{name}.png"), full_page=True)
        text = pg.inner_text("body")
        results[r] = {"console_errors": list(errors), "failed_requests": list(failed), "chars": len(text), "has_error_box": "Error" in text and "Insufficient" not in text}
        print(f"{r:60s} errors={len(errors)} failed={len(failed)} chars={len(text)}")
        for e in errors[:3]: print("   ", e[:200])
        for f in failed[:3]: print("   ", f[:200])
    b.close()
(out / "results.json").write_text(json.dumps(results, indent=1))
