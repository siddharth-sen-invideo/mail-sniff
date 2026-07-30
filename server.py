"""Mail Sniff FastAPI backend: bulk domain -> email discovery + export."""
from __future__ import annotations

import asyncio
import io
import uuid
from pathlib import Path
from typing import List, Optional

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import finder

app = FastAPI(title="Mail Sniff")

HERE = Path(__file__).parent
app.mount("/fonts", StaticFiles(directory=str(HERE / "fonts")), name="fonts")
app.mount("/assets", StaticFiles(directory=str(HERE / "assets")), name="assets")
MAX_DOMAINS = 500
DOMAIN_CONCURRENCY = 10

# in-memory job store
JOBS: dict[str, dict] = {}


class FindIn(BaseModel):
    domains: Optional[List[str]] = None
    text: Optional[str] = None


def _parse_domains(payload: FindIn) -> list[str]:
    items: list[str] = []
    if payload.domains:
        items.extend(payload.domains)
    if payload.text:
        for line in payload.text.replace(",", "\n").splitlines():
            line = line.strip()
            if line:
                items.append(line)
    # keep EXACT order, drop blanks; preserve duplicates (user's sequence is sacred)
    cleaned = [d.strip() for d in items if d.strip()]
    return cleaned[:MAX_DOMAINS]


async def _run_job(job_id: str, domains: list[str]):
    job = JOBS[job_id]
    sem = asyncio.Semaphore(DOMAIN_CONCURRENCY)
    limits = httpx.Limits(max_connections=40, max_keepalive_connections=20)
    timeout = httpx.Timeout(9.0, connect=6.0)
    async with httpx.AsyncClient(headers={"User-Agent": finder.UA}, follow_redirects=True,
                                 timeout=timeout, verify=False, limits=limits) as client:
        async def one(idx: int, dom: str):
            async with sem:
                try:
                    # hard ceiling so a bot-walled domain can't stall the batch
                    res = await asyncio.wait_for(finder.process_domain(client, dom), timeout=40)
                except asyncio.TimeoutError:
                    res = {"domain": dom, "normalized": finder.normalize_domain(dom),
                           "emails": [], "names": [], "found": False, "note": "timed out"}
                except Exception as e:  # never let one domain kill the batch
                    res = {"domain": dom, "normalized": finder.normalize_domain(dom),
                           "emails": [], "names": [], "found": False, "error": str(e)[:200]}
                res["confidence"] = finder.domain_confidence(res.get("emails", []))
                job["results"][idx] = res
                job["done"] += 1

        await asyncio.gather(*[one(i, d) for i, d in enumerate(domains)])
    job["running"] = False


@app.post("/api/find")
async def start_find(payload: FindIn):
    domains = _parse_domains(payload)
    if not domains:
        raise HTTPException(400, "No domains provided")
    job_id = uuid.uuid4().hex[:12]
    JOBS[job_id] = {
        "id": job_id,
        "total": len(domains),
        "done": 0,
        "running": True,
        "results": [
            {"domain": d, "normalized": finder.normalize_domain(d), "emails": [],
             "names": [], "found": None, "confidence": "pending"}
            for d in domains
        ],
    }
    asyncio.create_task(_run_job(job_id, domains))
    return {"job_id": job_id, "total": len(domains)}


@app.get("/api/job/{job_id}")
async def get_job(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(404, "job not found")
    found = sum(1 for r in job["results"] if r.get("found"))
    counts = {"high": 0, "medium": 0, "low": 0, "none": 0}
    for r in job["results"]:
        c = r.get("confidence")
        if c in counts and r.get("found") is not None:
            counts[c] += 1
    return {
        "id": job_id, "total": job["total"], "done": job["done"],
        "running": job["running"], "found": found, "counts": counts,
        "results": job["results"],
    }


def _flatten(job: dict):
    """Rows in EXACT input order: domain, emails(single cell), names, designation, confidence."""
    rows = []
    for r in job["results"]:
        emails = r.get("emails") or []
        names_cell = ", ".join(r.get("names") or [])
        desig_cell = ", ".join(r.get("designations") or [])
        li = r.get("linkedin") or {}
        if li.get("url"):
            who = " · ".join([x for x in [li.get("name"), li.get("role")] if x])
            li_cell = li["url"] + (f" ({who})" if who else "")
            if li.get("guess"):
                li_cell += " [search guess]"
        else:
            li_cell = ""
        if emails:
            email_cell = ", ".join(e["email"] for e in emails)
            conf = (r.get("confidence") or "").capitalize()
            detail = "; ".join(f'{e["email"]} ({e["label"]})' for e in emails)
        else:
            email_cell = "email not found"
            conf = "Not found"
            detail = ""
        rows.append([r["domain"], email_cell, names_cell, desig_cell, li_cell, conf, detail])
    return rows


@app.get("/api/job/{job_id}/export.csv")
async def export_csv(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(404, "job not found")
    import csv
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Domain", "Emails Found", "Names", "Designation", "LinkedIn (decision-maker)",
                "Confidence", "Detail"])
    for row in _flatten(job):
        w.writerow(row)
    data = "﻿" + buf.getvalue()  # BOM for Excel/Sheets
    return StreamingResponse(iter([data]), media_type="text/csv",
                             headers={"Content-Disposition": "attachment; filename=contacts.csv"})


@app.get("/api/job/{job_id}/export.xlsx")
async def export_xlsx(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(404, "job not found")
    try:
        import openpyxl
        from openpyxl.styles import Font, PatternFill, Alignment
    except Exception:
        raise HTTPException(500, "openpyxl not installed")
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Contacts"
    headers = ["Domain", "Emails Found", "Names", "Designation", "LinkedIn (decision-maker)",
               "Confidence", "Detail"]
    ws.append(headers)
    fill = PatternFill("solid", fgColor="0B0B12")
    font = Font(color="FFFFFF", bold=True)
    for c in range(1, len(headers) + 1):
        cell = ws.cell(row=1, column=c)
        cell.fill, cell.font = fill, font
        cell.alignment = Alignment(vertical="center")
    for row in _flatten(job):
        ws.append(row)
    widths = [28, 42, 22, 20, 46, 12, 52]
    for i, w in enumerate(widths, 1):
        ws.column_dimensions[openpyxl.utils.get_column_letter(i)].width = w
    ws.freeze_panes = "A2"
    bio = io.BytesIO()
    wb.save(bio)
    bio.seek(0)
    return StreamingResponse(
        bio, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": "attachment; filename=contacts.xlsx"})


@app.get("/", response_class=HTMLResponse)
async def index():
    return (HERE / "index.html").read_text(encoding="utf-8")


@app.get("/api/health")
async def health():
    return JSONResponse({"ok": True, "dns": finder._HAS_DNS})
