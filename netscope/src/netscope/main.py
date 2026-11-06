"""FastAPI service and static dashboard for NetScope."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from . import __version__
from .analyzer import analyze_packets
from .parser import PcapParseError, parse_pcap

PACKAGE_DIR = Path(__file__).resolve().parent
STATIC_DIR = PACKAGE_DIR / "static"
SAMPLE_PATH = PACKAGE_DIR / "data" / "demo-traffic.pcap"
MAX_UPLOAD_BYTES = int(os.getenv("NETSCOPE_MAX_UPLOAD_BYTES", str(12 * 1024 * 1024)))
MAX_PACKETS = int(os.getenv("NETSCOPE_MAX_PACKETS", "30000"))
MAX_REQUEST_BYTES = MAX_UPLOAD_BYTES + (128 * 1024)  # multipart boundaries and headers


class RequestBodyLimitMiddleware:
    """Enforce a request-size ceiling before multipart parsing can spool uploads."""

    def __init__(self, app, *, max_bytes: int, path: str) -> None:  # type: ignore[no-untyped-def]
        self.app = app
        self.max_bytes = max_bytes
        self.path = path

    async def __call__(self, scope, receive, send) -> None:  # type: ignore[no-untyped-def]
        if scope.get("type") != "http" or scope.get("path") != self.path or scope.get("method") != "POST":
            await self.app(scope, receive, send)
            return

        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        declared = headers.get(b"content-length")
        if declared:
            try:
                if int(declared) > self.max_bytes:
                    response = JSONResponse(status_code=413, content={"detail": "Request exceeds the configured upload limit."})
                    await response(scope, receive, send)
                    return
            except ValueError:
                response = JSONResponse(status_code=400, content={"detail": "Invalid Content-Length header."})
                await response(scope, receive, send)
                return

        received = 0

        class BodyLimitExceeded(Exception):
            pass

        async def limited_receive():  # type: ignore[no-untyped-def]
            nonlocal received
            message = await receive()
            if message.get("type") == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise BodyLimitExceeded
            return message

        try:
            await self.app(scope, limited_receive, send)
        except BodyLimitExceeded:
            response = JSONResponse(status_code=413, content={"detail": "Request exceeds the configured upload limit."})
            await response(scope, receive, send)


app = FastAPI(
    title="NetScope API",
    description="Explainable PCAP analysis, flow aggregation and network anomaly triage.",
    version=__version__,
    docs_url="/api/docs",
    redoc_url=None,
)
app.add_middleware(RequestBodyLimitMiddleware, max_bytes=MAX_REQUEST_BYTES, path="/api/analyze")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/healthz", tags=["health"])
def healthz() -> dict[str, str]:
    return {"status": "ok", "service": "netscope", "version": __version__}


def _set_analysis(result: dict[str, Any]) -> dict[str, Any]:
    app.state.current_analysis = result
    return result


def _current() -> dict[str, Any]:
    result = getattr(app.state, "current_analysis", None)
    if result is None:
        raise HTTPException(status_code=409, detail="No capture has been analysed yet. Load demo traffic or upload a PCAP.")
    return result


@app.post("/api/demo", tags=["analysis"])
def load_demo() -> dict[str, Any]:
    """Load the bundled synthetic PCAP and run all analysis rules."""
    if not SAMPLE_PATH.exists():
        raise HTTPException(status_code=500, detail="Bundled demo capture is missing from this deployment.")
    try:
        packets = parse_pcap(SAMPLE_PATH.read_bytes(), max_packets=MAX_PACKETS)
        result = analyze_packets(packets, filename="netscope-synthetic-demo.pcap")
    except (PcapParseError, ValueError) as exc:
        raise HTTPException(status_code=500, detail=f"Bundled sample could not be analysed: {exc}") from exc
    return _set_analysis(result)


@app.post("/api/analyze", tags=["analysis"])
def analyze_upload(file: UploadFile = File(...)) -> dict[str, Any]:
    """Analyse one uploaded classic PCAP in memory; the original file is not retained."""
    filename = Path(file.filename or "capture.pcap").name
    if Path(filename).suffix.lower() not in {".pcap", ".cap", ".dmp"}:
        raise HTTPException(status_code=415, detail="Upload a classic PCAP file with .pcap, .cap or .dmp extension.")
    contents = file.file.read(MAX_UPLOAD_BYTES + 1)
    if len(contents) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail=f"Capture exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MiB upload limit.")
    if not contents:
        raise HTTPException(status_code=400, detail="The uploaded capture is empty.")
    try:
        packets = parse_pcap(contents, max_packets=MAX_PACKETS)
        result = analyze_packets(packets, filename=filename)
    except PcapParseError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _set_analysis(result)


@app.get("/api/analysis", tags=["analysis"])
def get_analysis() -> dict[str, Any]:
    return _current()


@app.get("/api/export", tags=["analysis"])
def export_analysis() -> Response:
    result = _current()
    payload = json.dumps(result, indent=2, ensure_ascii=False)
    filename = "netscope-analysis.json"
    return Response(
        content=payload,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/sample.pcap", tags=["samples"])
def download_sample() -> FileResponse:
    if not SAMPLE_PATH.exists():
        raise HTTPException(status_code=404, detail="Sample capture not found.")
    return FileResponse(SAMPLE_PATH, media_type="application/vnd.tcpdump.pcap", filename="netscope-demo-traffic.pcap")


@app.get("/api/rules", tags=["analysis"])
def detection_rules() -> dict[str, Any]:
    result = _current()
    return {"rules": result["rules"]}


@app.exception_handler(Exception)
async def unexpected_error_handler(_request, exc: Exception):  # type: ignore[no-untyped-def]
    # Do not leak internal stack traces or packet contents to remote clients.
    return JSONResponse(status_code=500, content={"detail": "An unexpected analysis error occurred."})
