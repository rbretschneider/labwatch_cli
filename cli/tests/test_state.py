"""Tests for persistent state load/save."""

import json
from pathlib import Path

from labwatch.state import load_state, save_state


class TestLoadState:
    def test_load_missing_file(self, tmp_path):
        path = tmp_path / "nonexistent.json"
        assert load_state(path) == {}

    def test_load_valid_state(self, tmp_path):
        path = tmp_path / "state.json"
        path.write_text(json.dumps({"checks": {"disk": "ok"}}))
        state = load_state(path)
        assert state == {"checks": {"disk": "ok"}}

    def test_load_corrupt_json(self, tmp_path):
        path = tmp_path / "state.json"
        path.write_text("not valid json {{{")
        assert load_state(path) == {}

    def test_load_empty_file(self, tmp_path):
        path = tmp_path / "state.json"
        path.write_text("")
        assert load_state(path) == {}


class TestSaveState:
    def test_save_creates_file(self, tmp_path):
        path = tmp_path / "state.json"
        save_state({"checks": {"cpu": "warning"}}, path)
        assert path.exists()
        data = json.loads(path.read_text())
        assert data == {"checks": {"cpu": "warning"}}

    def test_save_creates_parent_dirs(self, tmp_path):
        path = tmp_path / "deep" / "nested" / "state.json"
        save_state({"hello": "world"}, path)
        assert path.exists()

    def test_save_overwrites_existing(self, tmp_path):
        path = tmp_path / "state.json"
        save_state({"v": 1}, path)
        save_state({"v": 2}, path)
        data = json.loads(path.read_text())
        assert data == {"v": 2}

    def test_roundtrip(self, tmp_path):
        path = tmp_path / "state.json"
        original = {"checks": {"disk": "ok", "cpu": "warning"}, "version": 1}
        save_state(original, path)
        loaded = load_state(path)
        assert loaded == original
