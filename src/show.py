#!/usr/bin/env python3
"""
Simple FastAPI server to browse CWE content saved under the `CWE/` directory.

Run:
  pip install -r requirements.txt
  uvicorn show:app --reload --port 8000

Open http://127.0.0.1:8000
"""
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import json
import os
from pathlib import Path
from typing import Optional

app = FastAPI(title="CWE Browser")

def _find_project_root(start: Path) -> Path:
    """Walk upwards to locate project root containing both `data/` and `templates/`."""
    p = start.resolve()
    for _ in range(6):
        if (p / "data").is_dir() and (p / "templates").is_dir():
            return p
        if p.parent == p:
            break
        p = p.parent
    return start.resolve()


PROJECT_ROOT = _find_project_root(Path(__file__).resolve().parent)
BASE = str(PROJECT_ROOT / "data")
templates = Jinja2Templates(directory=str(PROJECT_ROOT / "templates"))
static_dir = PROJECT_ROOT / "static"
if static_dir.is_dir():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


def load_json(path: str):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    # list weaknesses (IDs + Name)
    weaknesses_file = os.path.join(BASE, "weaknesses.json")
    weaknesses = load_json(weaknesses_file).get("Weaknesses") if load_json(weaknesses_file) else []
    
    # Sort weaknesses by integer ID
    weaknesses.sort(key=lambda w: int(w.get("ID", 0)))
    
    # Load specific view descendants for filtering
    # CWE-1000 (Research), CWE-699 (Software), CWE-1194 (Hardware)
    view_filters = {
        "Software Development": "699",
        "Hardware Design": "1194",
        "Research Concepts": "1000"
    }
    
    view_members = {}
    for name, vid in view_filters.items():
        desc_path = os.path.join(BASE, "relations", f"{vid}_descendants.json")
        desc = load_json(desc_path)
        ids = set()
        
        def traverse(nodes):
            if not nodes: return
            for n in nodes:
                data = n.get("Data", {})
                if "ID" in data:
                    ids.add(data["ID"])
                elif "ID" in n:
                    ids.add(n["ID"])
                traverse(n.get("Children", []))
                
        if desc:
            traverse(desc)
        
        view_members[vid] = list(ids)

    return templates.TemplateResponse("index.html", {
        "request": request, 
        "weaknesses": weaknesses,
        "view_members": json.dumps(view_members)
    })


@app.get("/weakness/{wid}", response_class=HTMLResponse)
def weakness_detail(request: Request, wid: str):
    path = os.path.join(BASE, "weaknesses", f"{wid}.json")
    obj = load_json(path)
    if not obj:
        raise HTTPException(status_code=404, detail="Weakness not found")
    # relations
    relations = {}
    rel_dir = os.path.join(BASE, "relations")
    for rel in ("parents", "children", "descendants", "ancestors"):
        rp = os.path.join(rel_dir, f"{wid}_{rel}.json")
        relations[rel] = load_json(rp)
    return templates.TemplateResponse("detail.html", {"request": request, "obj": obj, "relations": relations})

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(
        'show:app',
        host='127.0.0.1',
        port=8000,
        reload=True,
        reload_dirs=[str(PROJECT_ROOT)],
    )

