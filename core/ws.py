# core/ws.py
import json
from typing import List
from fastapi import WebSocket

class ConnectionManager:
    def __init__(self):
        self.active: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        # Accept and add to active connections
        await websocket.accept()
        self.active.append(websocket)

    def disconnect(self, websocket: WebSocket):
        try:
            self.active.remove(websocket)
        except ValueError:
            pass

    async def send_personal(self, websocket: WebSocket, message: dict):
        await websocket.send_text(json.dumps(message))

    async def broadcast(self, message: dict):
        text = json.dumps(message)
        # iterate copy to avoid mutation problems
        for ws in list(self.active):
            try:
                await ws.send_text(text)
            except Exception:
                # remove dead connections
                try:
                    self.active.remove(ws)
                except ValueError:
                    pass

# single shared manager used by the app
manager = ConnectionManager()
