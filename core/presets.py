"""
Preset manager — Load/Save/Delete camera presets from JSON file.
"""

import json
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional

PRESETS_FILE = Path(__file__).parent.parent / "presets.json"


@dataclass
class CameraPreset:
    name: str
    host: str
    onvif_port: int = 80
    rtsp_port: int = 554
    rtsp_path: str = "/stream1"
    username: str = "admin"
    password: str = ""
    auth_mode: str = "standard"      # "standard" | "custom"
    algorithm: str = "auto"          # "auto" | "MD5" | "SHA-256" | "SHA-512-256"
    quote_algo: bool = False
    protocol: str = "rtsp"           # "rtsp" | "rtsps"

    @property
    def onvif_url(self):
        return f"http://{self.host}:{self.onvif_port}/onvif/device_service"

    @property
    def rtsp_url(self):
        scheme = self.protocol
        return f"{scheme}://{self.host}:{self.rtsp_port}{self.rtsp_path}"

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, d):
        known = {f.name for f in cls.__dataclass_fields__.values()}
        return cls(**{k: v for k, v in d.items() if k in known})


class PresetManager:
    def __init__(self, filepath=None):
        self.filepath = Path(filepath) if filepath else PRESETS_FILE
        self._presets: list[CameraPreset] = []
        self.load()

    def load(self):
        if self.filepath.exists():
            try:
                with open(self.filepath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self._presets = [CameraPreset.from_dict(d) for d in data]
            except (json.JSONDecodeError, KeyError):
                self._presets = []
        else:
            self._presets = []

    def save(self):
        with open(self.filepath, "w", encoding="utf-8") as f:
            json.dump([p.to_dict() for p in self._presets], f, indent=2)

    def list_presets(self) -> list[CameraPreset]:
        return list(self._presets)

    def get(self, name: str) -> Optional[CameraPreset]:
        for p in self._presets:
            if p.name == name:
                return p
        return None

    def add(self, preset: CameraPreset):
        # Replace if same name exists
        self._presets = [p for p in self._presets if p.name != preset.name]
        self._presets.append(preset)
        self.save()

    def delete(self, name: str):
        self._presets = [p for p in self._presets if p.name != name]
        self.save()
