"""Tests for the scheduler module, including per-module scheduling."""

from unittest.mock import patch, MagicMock

from labwatch.scheduler import add_entry, parse_interval, list_entries, remove_entries


class TestParseInterval:

    def test_5m(self):
        assert parse_interval("5m") == "*/5 * * * *"

    def test_1h(self):
        assert parse_interval("1h") == "0 */1 * * *"

    def test_1d(self):
        assert parse_interval("1d") == "0 0 * * *"

    def test_30m(self):
        assert parse_interval("30m") == "*/30 * * * *"

    def test_invalid_raises(self):
        import pytest
        with pytest.raises(ValueError):
            parse_interval("abc")

    def test_invalid_unit_raises(self):
        import pytest
        with pytest.raises(ValueError):
            parse_interval("5x")

    def test_0m_raises(self):
        import pytest
        with pytest.raises(ValueError):
            parse_interval("0m")

    def test_2d_raises(self):
        import pytest
        with pytest.raises(ValueError):
            parse_interval("2d")


def _mock_crontab(existing=""):
    """Return read/write mocks for crontab manipulation."""
    stored = {"content": existing}

    def fake_run(cmd, **kwargs):
        if cmd == ["crontab", "-l"]:
            return MagicMock(returncode=0, stdout=stored["content"], stderr="")
        elif cmd == ["crontab", "-"]:
            stored["content"] = kwargs.get("input", "")
            return MagicMock(returncode=0, stderr="")
        return MagicMock(returncode=0, stdout="", stderr="")

    return stored, fake_run


class TestAddEntry:

    @patch("labwatch.scheduler.sys.platform", "linux")
    @patch("labwatch.scheduler.resolve_labwatch_path", return_value="/usr/bin/labwatch")
    @patch("labwatch.scheduler.subprocess.run")
    def test_basic_check_entry(self, mock_run, mock_path):
        stored, fake_run = _mock_crontab()
        mock_run.side_effect = fake_run

        line = add_entry("check", "5m")
        assert "*/5 * * * *" in line
        assert "/usr/bin/labwatch check" in line
        assert "# labwatch:check" in line
        assert "--only" not in line

    @patch("labwatch.scheduler.sys.platform", "linux")
    @patch("labwatch.scheduler.resolve_labwatch_path", return_value="/usr/bin/labwatch")
    @patch("labwatch.scheduler.subprocess.run")
    def test_per_module_entry(self, mock_run, mock_path):
        stored, fake_run = _mock_crontab()
        mock_run.side_effect = fake_run

        line = add_entry("check", "1m", modules=["network"])
        assert "*/1 * * * *" in line
        assert "--only network" in line
        assert "# labwatch:check:network" in line

    @patch("labwatch.scheduler.sys.platform", "linux")
    @patch("labwatch.scheduler.resolve_labwatch_path", return_value="/usr/bin/labwatch")
    @patch("labwatch.scheduler.subprocess.run")
    def test_multi_module_entry(self, mock_run, mock_path):
        stored, fake_run = _mock_crontab()
        mock_run.side_effect = fake_run

        line = add_entry("check", "30m", modules=["docker", "system"])
        assert "*/30 * * * *" in line
        assert "--only docker,system" in line
        assert "# labwatch:check:docker,system" in line

    @patch("labwatch.scheduler.sys.platform", "linux")
    @patch("labwatch.scheduler.resolve_labwatch_path", return_value="/usr/bin/labwatch")
    @patch("labwatch.scheduler.subprocess.run")
    def test_modules_sorted(self, mock_run, mock_path):
        stored, fake_run = _mock_crontab()
        mock_run.side_effect = fake_run

        line = add_entry("check", "5m", modules=["dns", "network", "http"])
        # Modules should be sorted for consistent markers
        assert "--only dns,http,network" in line
        assert "# labwatch:check:dns,http,network" in line

    @patch("labwatch.scheduler.sys.platform", "linux")
    @patch("labwatch.scheduler.resolve_labwatch_path", return_value="/usr/bin/labwatch")
    @patch("labwatch.scheduler.subprocess.run")
    def test_per_module_entries_coexist(self, mock_run, mock_path):
        stored, fake_run = _mock_crontab()
        mock_run.side_effect = fake_run

        add_entry("check", "1m", modules=["network"])
        add_entry("check", "30m", modules=["docker", "system"])
        add_entry("check", "5m", modules=["http"])

        # All three should exist in crontab
        lines = stored["content"].strip().splitlines()
        assert len(lines) == 3
        assert any("--only network" in l for l in lines)
        assert any("--only docker,system" in l for l in lines)
        assert any("--only http" in l for l in lines)

    @patch("labwatch.scheduler.sys.platform", "linux")
    @patch("labwatch.scheduler.resolve_labwatch_path", return_value="/usr/bin/labwatch")
    @patch("labwatch.scheduler.subprocess.run")
    def test_same_modules_replaces(self, mock_run, mock_path):
        stored, fake_run = _mock_crontab()
        mock_run.side_effect = fake_run

        add_entry("check", "1m", modules=["network"])
        add_entry("check", "5m", modules=["network"])  # change interval

        lines = stored["content"].strip().splitlines()
        assert len(lines) == 1
        assert "*/5 * * * *" in lines[0]

    @patch("labwatch.scheduler.sys.platform", "linux")
    @patch("labwatch.scheduler.resolve_labwatch_path", return_value="/usr/bin/labwatch")
    @patch("labwatch.scheduler.subprocess.run")
    def test_global_and_per_module_coexist(self, mock_run, mock_path):
        stored, fake_run = _mock_crontab()
        mock_run.side_effect = fake_run

        add_entry("check", "5m")  # global
        add_entry("check", "1m", modules=["network"])  # per-module

        lines = stored["content"].strip().splitlines()
        assert len(lines) == 2


class TestRemoveEntries:

    @patch("labwatch.scheduler.sys.platform", "linux")
    @patch("labwatch.scheduler.subprocess.run")
    def test_remove_check_removes_all_variants(self, mock_run):
        existing = (
            "*/5 * * * * /usr/bin/labwatch check # labwatch:check\n"
            "*/1 * * * * /usr/bin/labwatch check --only network # labwatch:check:network\n"
            "0 0 * * * /usr/bin/labwatch update # labwatch:update\n"
        )
        stored, fake_run = _mock_crontab(existing)
        mock_run.side_effect = fake_run

        removed = remove_entries("check")
        assert removed == 2
        # Only update entry should remain
        remaining = stored["content"].strip().splitlines()
        assert len(remaining) == 1
        assert "update" in remaining[0]
