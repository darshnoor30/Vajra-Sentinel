from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path

from app.services.pipeline import EventPipeline

LOGGER = logging.getLogger("vajra.eve")
MAX_LINE_BYTES = 2_000_000


class EveTailer:
    """Rotation-aware-enough EVE JSONL tailer for a single local sensor file."""

    def __init__(self, path: Path, pipeline: EventPipeline, sensor_id: str = "suricata-local"):
        self.path = path
        self.pipeline = pipeline
        self.sensor_id = sensor_id
        self._position = 0
        self._inode: int | None = None
        self._stopped = False

    def stop(self) -> None:
        self._stopped = True

    async def run(self) -> None:
        while not self._stopped:
            try:
                await asyncio.to_thread(self._poll_once)
            except Exception:
                LOGGER.exception("EVE ingestion poll failed")
            await asyncio.sleep(0.75)

    def _poll_once(self) -> None:
        if not self.path.exists():
            return
        stat = self.path.stat()
        if self._inode != stat.st_ino or stat.st_size < self._position:
            self._inode = stat.st_ino
            self._position = 0
        with self.path.open("rb") as handle:
            handle.seek(self._position)
            for line in handle:
                if len(line) > MAX_LINE_BYTES:
                    LOGGER.warning("Skipped oversized EVE record")
                    continue
                try:
                    raw = json.loads(line)
                    if isinstance(raw, dict):
                        self.pipeline.process(raw, self.sensor_id)
                except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
                    LOGGER.warning("Skipped invalid EVE JSON record")
            self._position = handle.tell()
