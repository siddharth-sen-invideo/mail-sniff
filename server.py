"""Mail Sniff FastAPI backend: bulk domain -> email discovery + export."""
from __future__ import annotations

import asyncio
import io
import os
import uuid
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import api
import finder
import runner

app = FastAPI(
    title="Mail Sniff",
    version="1.0.0",
    description=("Free contact-email discovery. Scrapes the site first, then finds "
                 "named people, and only guesses from the domain's own email "
                 "pattern as a last resort. See /docs for the REST API."),
)

# a browser-based client needs this; lock it down with ALLOWED_ORIGINS in prod
_origins = [o.strip() for o in os.environ.get("ALLOWED_ORIGINS", "*").split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware, allow_origins=_origins or ["*"], allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"], allow_headers=["*"],
)
app.include_router(api.router)

HERE = Path(__file__).parent
app.mount("/fonts", StaticFiles(directory=str(HERE / "fonts")), name="fonts")
app.mount("/assets", StaticFiles(directory=str(HERE / "assets")), name="assets")
MAX_DOMAINS = 500

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
    """Background batch scan. Uses runner's host-aware concurrency and client so
    the UI, the job API and the MCP server cannot drift apart: a hardcoded 5
    domains here starved the small Render instance and timed out every domain."""
    job = JOBS[job_id]
    sem = asyncio.Semaphore(runner.CONCURRENCY)
    async with runner.new_client() as client:
        async def one(idx: int, dom: str):
            async with sem:
                # the row is in flight now: the UI reads this to show a live bar
                # against the exact domains being crawled
                job["results"][idx]["state"] = "scanning"
                try:
                    res = await asyncio.wait_for(finder.process_domain(client, dom),
                                                 timeout=runner.PER_DOMAIN_TIMEOUT)
                except asyncio.TimeoutError:
                    res = {"domain": dom, "normalized": finder.normalize_domain(dom),
                           "emails": [], "names": [], "found": False, "note": "timed out"}
                except Exception as e:      # never let one domain kill the batch
                    res = {"domain": dom, "normalized": finder.normalize_domain(dom),
                           "emails": [], "names": [], "found": False,
                           "error": str(e)[:200]}
                res["confidence"] = finder.domain_confidence(res.get("emails", []))
                res["state"] = "done"
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
             "names": [], "found": None, "confidence": "pending", "state": "queued"}
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
    people = sum(len(r.get("people") or []) for r in job["results"])
    named = sum(1 for r in job["results"] if (r.get("people") or []))
    return {
        "id": job_id, "total": job["total"], "done": job["done"],
        "running": job["running"], "found": found, "counts": counts,
        "people": people, "named": named, "results": job["results"],
    }


def _flatten(job: dict):
    """Rows in EXACT input order: domain, emails(single cell), names, designation, confidence."""
    rows = []
    for r in job["results"]:
        emails = r.get("emails") or []
        names_cell = ", ".join(r.get("names") or [])
        desig_cell = ", ".join(r.get("designations") or [])
        ppl = r.get("people") or []
        people_cell = "\n".join(
            " | ".join(x for x in [p.get("name") or "", p.get("title") or "",
                                   p.get("email") or "",
                                   (p.get("status") or "").upper()] if x)
            for p in ppl) or "no named people found"
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
            detail = r.get("note") or ""
        rows.append([r["domain"], people_cell, email_cell, names_cell, desig_cell,
                     li_cell, conf, detail])
    return rows


@app.get("/api/job/{job_id}/export.csv")
async def export_csv(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(404, "job not found")
    import csv
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Domain", "People (name | title | email | status)", "Emails Found",
                "Names", "Designation", "LinkedIn (decision-maker)", "Confidence",
                "Detail"])
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
    headers = ["Domain", "People (name | title | email | status)", "Emails Found",
               "Names", "Designation", "LinkedIn (decision-maker)", "Confidence",
               "Detail"]
    ws.append(headers)
    fill = PatternFill("solid", fgColor="0B0B12")
    font = Font(color="FFFFFF", bold=True)
    for c in range(1, len(headers) + 1):
        cell = ws.cell(row=1, column=c)
        cell.fill, cell.font = fill, font
        cell.alignment = Alignment(vertical="center")
    for row in _flatten(job):
        ws.append(row)
    widths = [26, 60, 38, 20, 18, 42, 12, 46]
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
