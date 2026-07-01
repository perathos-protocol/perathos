import json

import pytest

from perathos.bundle import create_bundle
from perathos.storage import load_bundle, save_bundle


def test_save_and_load_bundle_roundtrip(tmp_path, monkeypatch):
    """Test that a bundle can be saved and loaded without corruption."""
    # Redirect bundles dir to temp directory
    monkeypatch.setenv("HOME", str(tmp_path))
    bundles_dir = tmp_path / ".perathos" / "bundles"
    bundles_dir.mkdir(parents=True, exist_ok=True)
    
    from perathos import storage
    monkeypatch.setattr(storage, "bundles_dir", lambda: bundles_dir)
    
    b = create_bundle("test output", input_text="test input")
    path = save_bundle(b)
    
    assert path.exists()
    loaded = load_bundle(b["bundle_id"])
    assert loaded == b


def test_load_bundle_not_found():
    """Test that load_bundle raises FileNotFoundError for non-existent bundle."""
    with pytest.raises(FileNotFoundError):
        load_bundle("nonexistent-bundle-id")


def test_load_bundle_with_truncated_json(tmp_path, monkeypatch):
    """Test that load_bundle handles truncated JSON gracefully."""
    bundles_dir = tmp_path / ".perathos" / "bundles"
    bundles_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HOME", str(tmp_path))
    
    from perathos import storage
    monkeypatch.setattr(storage, "bundles_dir", lambda: bundles_dir)
    
    # Create a truncated JSON file
    bundle_id = "550e8400-e29b-41d4-a716-446655440000"
    path = bundles_dir / f"{bundle_id}.json"
    path.write_text('{"bundle_id": "550e8400-e29b-41d4-a716-4466554400')
    
    with pytest.raises(json.JSONDecodeError):
        load_bundle(bundle_id)


def test_load_bundle_with_empty_json_file(tmp_path, monkeypatch):
    """Test that load_bundle handles empty JSON file gracefully."""
    bundles_dir = tmp_path / ".perathos" / "bundles"
    bundles_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HOME", str(tmp_path))
    
    from perathos import storage
    monkeypatch.setattr(storage, "bundles_dir", lambda: bundles_dir)
    
    # Create an empty JSON file
    bundle_id = "550e8400-e29b-41d4-a716-446655440000"
    path = bundles_dir / f"{bundle_id}.json"
    path.write_text('')
    
    with pytest.raises(json.JSONDecodeError):
        load_bundle(bundle_id)


def test_load_bundle_with_invalid_json(tmp_path, monkeypatch):
    """Test that load_bundle handles invalid JSON gracefully."""
    bundles_dir = tmp_path / ".perathos" / "bundles"
    bundles_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HOME", str(tmp_path))
    
    from perathos import storage
    monkeypatch.setattr(storage, "bundles_dir", lambda: bundles_dir)
    
    # Create a file with invalid JSON
    bundle_id = "550e8400-e29b-41d4-a716-446655440000"
    path = bundles_dir / f"{bundle_id}.json"
    path.write_text('this is not json at all {[[')
    
    with pytest.raises(json.JSONDecodeError):
        load_bundle(bundle_id)


def test_load_bundle_with_json_null(tmp_path, monkeypatch):
    """Test that load_bundle handles JSON null gracefully."""
    bundles_dir = tmp_path / ".perathos" / "bundles"
    bundles_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HOME", str(tmp_path))
    
    from perathos import storage
    monkeypatch.setattr(storage, "bundles_dir", lambda: bundles_dir)
    
    # Create a JSON file containing null
    bundle_id = "550e8400-e29b-41d4-a716-446655440000"
    path = bundles_dir / f"{bundle_id}.json"
    path.write_text('null')
    
    # load_bundle should return None, which is what json.loads returns for null
    result = load_bundle(bundle_id)
    assert result is None


def test_load_bundle_with_json_array(tmp_path, monkeypatch):
    """Test that load_bundle handles JSON array (not dict) gracefully."""
    bundles_dir = tmp_path / ".perathos" / "bundles"
    bundles_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HOME", str(tmp_path))
    
    from perathos import storage
    monkeypatch.setattr(storage, "bundles_dir", lambda: bundles_dir)
    
    # Create a JSON file containing an array instead of object
    bundle_id = "550e8400-e29b-41d4-a716-446655440000"
    path = bundles_dir / f"{bundle_id}.json"
    path.write_text('[1, 2, 3]')
    
    # load_bundle should return the array
    result = load_bundle(bundle_id)
    assert result == [1, 2, 3]


def test_load_bundle_with_json_string(tmp_path, monkeypatch):
    """Test that load_bundle handles JSON string (not dict) gracefully."""
    bundles_dir = tmp_path / ".perathos" / "bundles"
    bundles_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HOME", str(tmp_path))
    
    from perathos import storage
    monkeypatch.setattr(storage, "bundles_dir", lambda: bundles_dir)
    
    # Create a JSON file containing a string instead of object
    bundle_id = "550e8400-e29b-41d4-a716-446655440000"
    path = bundles_dir / f"{bundle_id}.json"
    path.write_text('"just a string"')
    
    # load_bundle should return the string
    result = load_bundle(bundle_id)
    assert result == "just a string"


def test_load_bundle_with_json_number(tmp_path, monkeypatch):
    """Test that load_bundle handles JSON number (not dict) gracefully."""
    bundles_dir = tmp_path / ".perathos" / "bundles"
    bundles_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HOME", str(tmp_path))
    
    from perathos import storage
    monkeypatch.setattr(storage, "bundles_dir", lambda: bundles_dir)
    
    # Create a JSON file containing a number instead of object
    bundle_id = "550e8400-e29b-41d4-a716-446655440000"
    path = bundles_dir / f"{bundle_id}.json"
    path.write_text('42')
    
    # load_bundle should return the number
    result = load_bundle(bundle_id)
    assert result == 42


def test_load_bundle_with_json_boolean(tmp_path, monkeypatch):
    """Test that load_bundle handles JSON boolean (not dict) gracefully."""
    bundles_dir = tmp_path / ".perathos" / "bundles"
    bundles_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HOME", str(tmp_path))
    
    from perathos import storage
    monkeypatch.setattr(storage, "bundles_dir", lambda: bundles_dir)
    
    # Create a JSON file containing a boolean instead of object
    bundle_id = "550e8400-e29b-41d4-a716-446655440000"
    path = bundles_dir / f"{bundle_id}.json"
    path.write_text('true')
    
    # load_bundle should return the boolean
    result = load_bundle(bundle_id)
    assert result is True


def test_load_bundle_missing_bundle_id_field(tmp_path, monkeypatch):
    """Test that load_bundle returns a dict even when bundle_id field is missing."""
    bundles_dir = tmp_path / ".perathos" / "bundles"
    bundles_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HOME", str(tmp_path))
    
    from perathos import storage
    monkeypatch.setattr(storage, "bundles_dir", lambda: bundles_dir)
    
    # Create a JSON file with a dict but missing bundle_id
    bundle_id = "550e8400-e29b-41d4-a716-446655440000"
    path = bundles_dir / f"{bundle_id}.json"
    path.write_text('{"integrity_hash": "abc123", "output_hash": "def456"}')
    
    result = load_bundle(bundle_id)
    assert isinstance(result, dict)
    assert "bundle_id" not in result
    assert result["integrity_hash"] == "abc123"


def test_load_bundle_missing_integrity_hash_field(tmp_path, monkeypatch):
    """Test that load_bundle returns a dict even when integrity_hash field is missing."""
    bundles_dir = tmp_path / ".perathos" / "bundles"
    bundles_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HOME", str(tmp_path))
    
    from perathos import storage
    monkeypatch.setattr(storage, "bundles_dir", lambda: bundles_dir)
    
    # Create a JSON file with a dict but missing integrity_hash
    bundle_id = "550e8400-e29b-41d4-a716-446655440000"
    path = bundles_dir / f"{bundle_id}.json"
    path.write_text('{"bundle_id": "550e8400-e29b-41d4-a716-446655440000", "output_hash": "def456"}')
    
    result = load_bundle(bundle_id)
    assert isinstance(result, dict)
    assert "integrity_hash" not in result
    assert result["bundle_id"] == "550e8400-e29b-41d4-a716-446655440000"


def test_load_bundle_missing_trace_field(tmp_path, monkeypatch):
    """Test that load_bundle returns a dict even when _trace field is missing."""
    bundles_dir = tmp_path / ".perathos" / "bundles"
    bundles_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HOME", str(tmp_path))
    
    from perathos import storage
    monkeypatch.setattr(storage, "bundles_dir", lambda: bundles_dir)
    
    # Create a JSON file with a dict but missing _trace
    bundle_id = "550e8400-e29b-41d4-a716-446655440000"
    path = bundles_dir / f"{bundle_id}.json"
    path.write_text('{"bundle_id": "550e8400-e29b-41d4-a716-446655440000", "integrity_hash": "abc123"}')
    
    result = load_bundle(bundle_id)
    assert isinstance(result, dict)
    assert "_trace" not in result


def test_load_bundle_missing_multiple_critical_fields(tmp_path, monkeypatch):
    """Test load_bundle with a dict missing multiple critical fields."""
    bundles_dir = tmp_path / ".perathos" / "bundles"
    bundles_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HOME", str(tmp_path))
    
    from perathos import storage
    monkeypatch.setattr(storage, "bundles_dir", lambda: bundles_dir)
    
    # Create a JSON file with a dict missing bundle_id, integrity_hash, and _trace
    bundle_id = "550e8400-e29b-41d4-a716-446655440000"
    path = bundles_dir / f"{bundle_id}.json"
    path.write_text('{"output_hash": "xyz789", "issued_at": "2024-01-01T00:00:00Z"}')
    
    result = load_bundle(bundle_id)
    assert isinstance(result, dict)
    assert "bundle_id" not in result
    assert "integrity_hash" not in result
    assert "_trace" not in result
    assert result["output_hash"] == "xyz789"


def test_load_bundle_with_empty_dict(tmp_path, monkeypatch):
    """Test that load_bundle handles an empty dict gracefully."""
    bundles_dir = tmp_path / ".perathos" / "bundles"
    bundles_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HOME", str(tmp_path))
    
    from perathos import storage
    monkeypatch.setattr(storage, "bundles_dir", lambda: bundles_dir)
    
    # Create a JSON file with an empty dict
    bundle_id = "550e8400-e29b-41d4-a716-446655440000"
    path = bundles_dir / f"{bundle_id}.json"
    path.write_text('{}')
    
    result = load_bundle(bundle_id)
    assert isinstance(result, dict)
    assert result == {}


def test_save_bundle_stores_all_fields(tmp_path, monkeypatch):
    """Test that save_bundle preserves all bundle fields."""
    bundles_dir = tmp_path / ".perathos" / "bundles"
    bundles_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HOME", str(tmp_path))
    
    from perathos import storage
    monkeypatch.setattr(storage, "bundles_dir", lambda: bundles_dir)
    
    b = create_bundle("output", input_text="input")
    path = save_bundle(b)
    
    # Read back the raw JSON to verify all fields are present
    raw_json = json.loads(path.read_text(encoding="utf-8"))
    for key in b:
        assert key in raw_json
        assert raw_json[key] == b[key]


def test_save_bundle_json_is_valid(tmp_path, monkeypatch):
    """Test that save_bundle creates valid, parseable JSON."""
    bundles_dir = tmp_path / ".perathos" / "bundles"
    bundles_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HOME", str(tmp_path))
    
    from perathos import storage
    monkeypatch.setattr(storage, "bundles_dir", lambda: bundles_dir)
    
    b = create_bundle("output")
    path = save_bundle(b)
    
    # Should not raise
    loaded = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
