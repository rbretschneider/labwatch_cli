"""Tests for environment variable interpolation in config."""

import os
from unittest.mock import patch

from labwatch.config import _expand_env_vars


class TestExpandEnvVars:
    def test_simple_string_expansion(self):
        with patch.dict(os.environ, {"MY_TOKEN": "secret123"}):
            assert _expand_env_vars("${MY_TOKEN}") == "secret123"

    def test_unset_var_left_as_is(self):
        env = os.environ.copy()
        env.pop("NONEXISTENT_VAR_XYZ", None)
        with patch.dict(os.environ, env, clear=True):
            assert _expand_env_vars("${NONEXISTENT_VAR_XYZ}") == "${NONEXISTENT_VAR_XYZ}"

    def test_string_with_surrounding_text(self):
        with patch.dict(os.environ, {"HOST": "example.com"}):
            assert _expand_env_vars("https://${HOST}/api") == "https://example.com/api"

    def test_multiple_vars_in_string(self):
        with patch.dict(os.environ, {"HOST": "example.com", "PORT": "8080"}):
            result = _expand_env_vars("${HOST}:${PORT}")
            assert result == "example.com:8080"

    def test_dict_recursion(self):
        with patch.dict(os.environ, {"TOKEN": "abc"}):
            obj = {"nested": {"key": "${TOKEN}"}}
            result = _expand_env_vars(obj)
            assert result == {"nested": {"key": "abc"}}

    def test_list_recursion(self):
        with patch.dict(os.environ, {"ITEM": "val"}):
            obj = ["${ITEM}", "literal"]
            result = _expand_env_vars(obj)
            assert result == ["val", "literal"]

    def test_non_string_passthrough(self):
        assert _expand_env_vars(42) == 42
        assert _expand_env_vars(True) is True
        assert _expand_env_vars(None) is None

    def test_mixed_structure(self):
        with patch.dict(os.environ, {"SERVER": "ntfy.sh", "TOPIC": "alerts"}):
            obj = {
                "server": "https://${SERVER}",
                "topic": "${TOPIC}",
                "port": 443,
                "tags": ["${TOPIC}", "extra"],
            }
            result = _expand_env_vars(obj)
            assert result["server"] == "https://ntfy.sh"
            assert result["topic"] == "alerts"
            assert result["port"] == 443
            assert result["tags"] == ["alerts", "extra"]

    def test_empty_string(self):
        assert _expand_env_vars("") == ""

    def test_no_vars_in_string(self):
        assert _expand_env_vars("plain text") == "plain text"
