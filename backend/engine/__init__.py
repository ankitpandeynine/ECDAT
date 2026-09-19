# ECDAT Engine Package
import sys

try:
    import yaml
except ImportError:
    import json
    from pathlib import Path

    class _YamlCompat:
        @staticmethod
        def safe_load(stream):
            text = stream.read() if hasattr(stream, "read") else stream
            if hasattr(stream, "name"):
                try:
                    json_path = Path(stream.name).with_suffix(".json")
                    if json_path.exists():
                        with open(json_path, "r", encoding="utf-8") as jf:
                            return json.load(jf)
                except Exception:
                    pass
            try:
                return json.loads(text)
            except Exception:
                return {}

    _compat_mod = types.ModuleType("yaml")
    _compat_mod.safe_load = _YamlCompat.safe_load
    sys.modules["yaml"] = _compat_mod
