import json
import tempfile
from pathlib import Path

import pytest

from perathos.storage import load_bundle, save_bundle


def test_load_bundle_missing():
    """load_bundle raises FileNotFoundError for nonexistent bundle."""
    with pytest.raises(FileNotFoundError):
        load_bundle("nonexistent-id")


def test_load_bundle_malformed_json():
    """load_bundle raises ValueError for malformed JSON."""
    with tempfile.TemporaryDirectory() as tmpdir:
        bundles_file = Path(tmpdir) / "bad.json"
        bundles_file.write_text("{invalid json")
        bundle_id = bundles_file.stem
        
        # Temporarily patch bundles_dir to return our temp directory
        import perathos.storage
        original_bundles_dir = perathos.storage.bundles_dir
        perathos.storage.bundles_dir = lambda: Path(tmpdir)
        
        try:
            with pytest.raises(ValueError, match="Invalid JSON"):
                load_bundle(bundle_id)
        finally:
            perathos.storage.bundles_dir = original_bundles_dir


def test_save_and_load_bundle_roundtrip():
    """save_bundle and load_bundle work together."""
    bundle = {
        "bundle_id": "test-uuid",
        "proof_system": "sha256-deterministic",
        "ai_id": "test-ai-id",
    }
    
    # Use a temporary directory
    import perathos.storage
    original_bundles_dir = perathos.storage.bundles_dir
    
    with tempfile.TemporaryDirectory() as tmpdir:
        perathos.storage.bundles_dir = lambda: Path(tmpdir)
        
        try:
            path = save_bundle(bundle)
            assert path.exists()
            assert path.name == "test-uuid.json"
            
            loaded = load_bundle("test-uuid")
            assert loaded == bundle
        finally:
            perathos.storage.bundles_dir = original_bundles_dir
