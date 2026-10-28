import json
import asyncio
from typing import Set
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel
from engine import MultiStageCorrelationEngine

app = FastAPI(title="Multi-Stage Attack Detection & Correlation Engine")
engine = MultiStageCorrelationEngine(time_window_seconds=300)

app.mount("/static", StaticFiles(directory="static"), name="static")

class TelemetryLog(BaseModel):
    source_ip: str
    user: str = "system"
    endpoint: str
    event_type: str
    payload_bytes: int = 420
    req_rate: float = 10.0
    sensitivity: int = 2
    status_code: int = 200

class EventBroadcaster:
    def __init__(self):
        self.listeners: Set[asyncio.Queue] = set()

    async def connect(self) -> asyncio.Queue:
        q = asyncio.Queue()
        self.listeners.add(q)
        return q

    def disconnect(self, q: asyncio.Queue):
        if q in self.listeners:
            self.listeners.remove(q)

    async def broadcast(self, data: dict):
        for q in self.listeners:
            await q.put(data)

broadcaster = EventBroadcaster()

@app.get("/")
async def serve_ui():
    return FileResponse("static/index.html")

@app.post("/api/v1/ingest")
async def ingest_log(log: TelemetryLog):
    result = engine.process_event(log.model_dump())
    await broadcaster.broadcast(result)
    return {"status": "ingested", "risk_score": result["correlation"]["risk_score"]}

@app.post("/api/v1/reset")
async def reset_engine():
    engine.ip_history.clear()
    await broadcaster.broadcast({"type": "RESET"})
    return {"status": "state_cleared"}

@app.get("/api/v1/stream")
async def stream_events(request: Request):
    async def event_generator():
        q = await broadcaster.connect()
        try:
            while True:
                if await request.is_disconnected():
                    break
                data = await q.get()
                yield f"data: {json.dumps(data)}\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            broadcaster.disconnect(q)

    return StreamingResponse(event_generator(), media_type="text/event-stream")