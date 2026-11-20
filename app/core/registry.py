"""Collector registry module for loading and validating trusted Tier 1 collectors from YAML."""
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import yaml
from cryptography.hazmat.primitives.asymmetric import ed25519

import app.config as config
from app.core.crypto import load_ed25519_public_key_from_pem_file

logger = logging.getLogger(__name__)


@dataclass
class CollectorRegistration:
    collector_id: str
    tenant_id: str
    public_key_path: Path
    active: bool
    public_key: ed25519.Ed25519PublicKey


class CollectorRegistry:
    """Registry maintaining active trusted Tier 1 collectors."""

    def __init__(self, config_path: Optional[Path] = None):
        self._custom_config_path = config_path
        self._collectors: dict[str, CollectorRegistration] = {}

    @property
    def config_path(self) -> Path:
        return self._custom_config_path or config.COLLECTORS_CONFIG_PATH

    @config_path.setter
    def config_path(self, val: Path):
        self._custom_config_path = val

    def reload(self) -> None:
        """Loads or reloads collectors from the YAML configuration."""
        cfg = self.config_path
        if not cfg.is_file():
            logger.warning("Collector config file not found at %s", cfg)
            self._collectors.clear()
            return

        with open(cfg, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        collectors_list = data.get("collectors", [])
        new_registry: dict[str, CollectorRegistration] = {}

        for entry in collectors_list:
            cid = entry.get("collector_id")
            tid = entry.get("tenant_id")
            key_rel_path = entry.get("public_key_path")
            active = bool(entry.get("active", True))

            if not cid or not tid or not key_rel_path:
                logger.error("Skipping invalid collector entry: %s", entry)
                continue

            key_path = Path(key_rel_path)
            if not key_path.is_absolute():
                key_path = config.BASE_DIR / key_path

            try:
                public_key = load_ed25519_public_key_from_pem_file(key_path)
            except Exception as e:
                logger.error("Failed to load public key for collector '%s' from %s: %s", cid, key_path, e)
                continue

            new_registry[cid] = CollectorRegistration(
                collector_id=cid,
                tenant_id=tid,
                public_key_path=key_path,
                active=active,
                public_key=public_key,
            )

        self._collectors = new_registry
        logger.info("Loaded %d collectors into registry", len(self._collectors))

    def get(self, collector_id: str) -> Optional[CollectorRegistration]:
        return self._collectors.get(collector_id)

    def list_all(self) -> list[CollectorRegistration]:
        return list(self._collectors.values())


# Global singleton registry
registry = CollectorRegistry()
