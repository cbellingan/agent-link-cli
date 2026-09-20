"""Named connection profile management for agent-link-cli.

Enables agents and human operators to configure named connection profiles
(server URL and default agent ID) without repeatedly passing flags or embedding secrets.
Profiles are persisted in profiles.json within the configured state directory.
"""

from __future__ import annotations
import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from agent_link.security import AgentLinkSecurityError


class ProfileManager:
    """Manages persistent named connection profiles."""

    def __init__(self, state_dir: Optional[Path] = None):
        if state_dir is not None:
            self.state_dir = Path(state_dir)
        elif os.environ.get("AGENT_LINK_STATE_DIR"):
            self.state_dir = Path(os.environ["AGENT_LINK_STATE_DIR"])
        else:
            self.state_dir = Path.home() / ".agent-link"

        self.profiles_file = self.state_dir / "profiles.json"
        self._data: Dict[str, Any] = {"active_profile": None, "profiles": {}}
        self._load()

    def _load(self) -> None:
        if self.profiles_file.exists():
            try:
                content = json.loads(self.profiles_file.read_text(encoding="utf-8"))
                if isinstance(content, dict):
                    self._data = {
                        "active_profile": content.get("active_profile"),
                        "profiles": content.get("profiles", {}),
                    }
            except Exception:
                self._data = {"active_profile": None, "profiles": {}}
        else:
            self._data = {"active_profile": None, "profiles": {}}

    def _save(self) -> None:
        try:
            self.state_dir.mkdir(parents=True, exist_ok=True)
            tmp_file = self.state_dir / f".profiles.tmp.{os.getpid()}_{time.time()}"
            tmp_file.write_text(json.dumps(self._data, indent=2), encoding="utf-8")
            os.replace(tmp_file, self.profiles_file)
        except Exception as e:
            raise AgentLinkSecurityError(f"Profile persistence failed: {e}") from e

    def set_profile(
        self,
        name: str,
        server_url: str,
        agent_id: Optional[str] = None,
        is_default: bool = False,
    ) -> Dict[str, Any]:
        """Create or update a named connection profile."""
        clean_name = name.strip()
        if not clean_name:
            raise ValueError("Profile name cannot be empty")

        clean_server = server_url.strip().rstrip("/")
        if not clean_server:
            raise ValueError("Server URL cannot be empty")

        self._load()
        existing = self._data["profiles"].get(clean_name, {})
        now = time.time()

        profile = {
            "name": clean_name,
            "server_url": clean_server,
            "agent_id": (agent_id.strip() if agent_id else existing.get("agent_id")) or None,
            "created_at": existing.get("created_at", now),
            "updated_at": now,
        }

        self._data["profiles"][clean_name] = profile

        # Set as active profile if requested or if it's the only profile
        if is_default or not self._data["active_profile"] or len(self._data["profiles"]) == 1:
            self._data["active_profile"] = clean_name

        self._save()
        return profile

    def get_profile(self, name: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Retrieve a profile by name, or the active profile if name is None."""
        self._load()
        target_name = name or self._data.get("active_profile")
        if not target_name:
            # If no active profile is set but profiles exist, use 'default' or the first one
            if "default" in self._data["profiles"]:
                target_name = "default"
            elif self._data["profiles"]:
                target_name = next(iter(self._data["profiles"]))

        if target_name:
            return self._data["profiles"].get(target_name)
        return None

    def list_profiles(self) -> List[Dict[str, Any]]:
        """List all configured profiles with active status indicated."""
        self._load()
        active = self._data.get("active_profile")
        result = []
        for name, p in self._data["profiles"].items():
            entry = dict(p)
            entry["is_active"] = (name == active)
            result.append(entry)
        return sorted(result, key=lambda x: x["name"])

    def use_profile(self, name: str) -> None:
        """Set the active/default profile."""
        clean_name = name.strip()
        self._load()
        if clean_name not in self._data["profiles"]:
            raise ValueError(f"Profile '{clean_name}' does not exist")
        self._data["active_profile"] = clean_name
        self._save()

    def remove_profile(self, name: str) -> bool:
        """Remove a profile by name."""
        clean_name = name.strip()
        self._load()
        if clean_name not in self._data["profiles"]:
            return False

        del self._data["profiles"][clean_name]
        if self._data.get("active_profile") == clean_name:
            # Fall back to 'default' or next available profile
            if "default" in self._data["profiles"]:
                self._data["active_profile"] = "default"
            elif self._data["profiles"]:
                self._data["active_profile"] = next(iter(self._data["profiles"]))
            else:
                self._data["active_profile"] = None

        self._save()
        return True
