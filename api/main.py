import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from datetime import datetime, timezone

from scanner.aws_scanner import AWSScanner
from rules.rule_engine import run_rules
from llm.ollama_explainer import enrich_findings, check_ollama_running

app = FastAPI(title="CloudSentinel")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

_state = {"findings": [], "summary": {}, "resolved": set(), "scan_history": [], "last_scan": None}

@app.get("/api/status")
def status():
    up = check_ollama_running()
    return {"ollama_available": up, "last_scan": _state["last_scan"], "total_findings": len(_state["findings"])}

@app.get("/api/scan")
def scan(mock: bool = True):
    data   = AWSScanner(use_mock=mock).scan_all()
    result = run_rules(data)
    for i, f in enumerate(result["findings"]):
        f["finding_id"] = f"finding-{i+1:03d}"
        f["status"]     = "resolved" if f["finding_id"] in _state["resolved"] else "open"
    up       = check_ollama_running()
    enriched = enrich_findings(result["findings"], use_ollama=up)
    _state.update({"findings": enriched, "summary": result["summary"], "last_scan": datetime.now(timezone.utc).isoformat()})
    _state["scan_history"].append({"scanned_at": _state["last_scan"], "risk_score": result["summary"]["risk_score"]})
    return {"summary": _state["summary"], "findings": _active(), "scan_history": _state["scan_history"], "ollama_used": up}

@app.get("/api/findings")
def findings():
    if not _state["findings"]: raise HTTPException(404, "Run /api/scan first")
    return {"summary": _state["summary"], "findings": _active(), "scan_history": _state["scan_history"]}

@app.post("/api/fix/{fid}")
def resolve(fid: str):
    _state["resolved"].add(fid)
    f = _get(fid)
    if f: f["status"] = "resolved"
    return {"message": f"{fid} resolved"}

@app.post("/api/fix/{fid}/reopen")
def reopen(fid: str):
    _state["resolved"].discard(fid)
    f = _get(fid)
    if f: f["status"] = "open"
    return {"message": f"{fid} reopened"}

def _get(fid):   return next((f for f in _state["findings"] if f.get("finding_id") == fid), None)
def _active():   return [f for f in _state["findings"] if f.get("status") != "resolved"]

frontend = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.exists(os.path.join(frontend, "index.html")):
    app.mount("/static", StaticFiles(directory=frontend), name="static")
    @app.get("/")
    def ui(): return FileResponse(os.path.join(frontend, "index.html"))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
