"""Tests for the scheduler module, including per-module scheduling and sentinel blocks."""

from unittest.mock import patch, MagicMock

from labwatch.scheduler import (
    add_entry, parse_interval, list_entries, remove_entries,
    _SENTINEL_BEGIN, _SENTINEL_END, _split_crontab, _join_crontab,
)


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


# ---------------------------------------------------------------------------
# Sentinel block helpers
# ---------------------------------------------------------------------------

class TestSplitCrontab:

    def test_empty(self):
        user, lw = _split_crontab("")
        assert user == []
        assert lw == []

    def test_user_only(self):
        raw = "0 * * * * /usr/bin/backup.sh\n"
        user, lw = _split_crontab(raw)
        assert user == ["0 * * * * /usr/bin/backup.sh"]
        assert lw == []

    def test_sentinel_block(self):
        raw = (
            "0 * * * * /usr/bin/backup.sh\n"
            f"{_SENTINEL_BEGIN}\n"
            "*/5 * * * * /usr/bin/labwatch check # labwatch:check\n"
            f"{_SENTINEL_END}\n"
        )
        user, lw = _split_crontab(raw)
        assert len(user) == 1
        assert "backup" in user[0]
        assert len(lw) == 1
        assert "labwatch:check" in lw[0]

    def test_legacy_entries_migrated(self):
        """labwatch entries without sentinel block are adopted into lw bucket."""
        raw = (
            "0 * * * * /usr/bin/backup.sh\n"
            "*/5 * * * * /usr/bin/labwatch check # labwatch:check\n"
        )
        user, lw = _split_crontab(raw)
        assert len(user) == 1
        assert "backup" in user[0]
        assert len(lw) == 1
        assert "labwatch:check" in lw[0]

    def test_sentinels_not_in_output(self):
        """Sentinel comments themselves should not appear in either bucket."""
        raw = (
            f"{_SENTINEL_BEGIN}\n"
            "*/5 * * * * /usr/bin/labwatch check # labwatch:check\n"
            f"{_SENTINEL_END}\n"
        )
        user, lw = _split_crontab(raw)
        for line in user + lw:
            assert _SENTINEL_BEGIN not in line
            assert _SENTINEL_END not in line


class TestJoinCrontab:

    def test_empty(self):
        assert _join_crontab([], []) == ""

    def test_user_only(self):
        result = _join_crontab(["0 * * * * /usr/bin/backup.sh"], [])
        assert _SENTINEL_BEGIN not in result
        assert result.strip() == "0 * * * * /usr/bin/backup.sh"

    def test_lw_only(self):
        result = _join_crontab([], ["*/5 * * * * labwatch check # labwatch:check"])
        assert _SENTINEL_BEGIN in result
        assert _SENTINEL_END in result
        assert "labwatch check" in result

    def test_both(self):
        result = _join_crontab(
            ["0 * * * * /usr/bin/backup.sh"],
            ["*/5 * * * * labwatch check # labwatch:check"],
        )
        lines = result.splitlines()
        assert lines[0] == "0 * * * * /usr/bin/backup.sh"
        # Sentinel block should appear after user lines
        assert _SENTINEL_BEGIN in result
        assert _SENTINEL_END in result
        begin_idx = lines.index(_SENTINEL_BEGIN)
        end_idx = lines.index(_SENTINEL_END)
        assert begin_idx < end_idx

    def test_trailing_newline(self):
        result = _join_crontab(["foo"], ["bar # labwatch:x"])
        assert result.endswith("\n")


# ---------------------------------------------------------------------------
# add_entry
# ---------------------------------------------------------------------------

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
        assert "1-59/1 * * * *" in line
        assert "--only network" in line
        assert "# labwatch:check:network" in line

    @patch("labwatch.scheduler.sys.platform", "linux")
    @patch("labwatch.scheduler.resolve_labwatch_path", return_value="/usr/bin/labwatch")
    @patch("labwatch.scheduler.subprocess.run")
    def test_multi_module_entry(self, mock_run, mock_path):
        stored, fake_run = _mock_crontab()
        mock_run.side_effect = fake_run

        line = add_entry("check", "30m", modules=["docker", "system"])
        assert "1-59/30 * * * *" in line
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
        content = stored["content"]
        assert content.count("--only network") == 1
        assert content.count("--only docker,system") == 1
        assert content.count("--only http") == 1

    @patch("labwatch.scheduler.sys.platform", "linux")
    @patch("labwatch.scheduler.resolve_labwatch_path", return_value="/usr/bin/labwatch")
    @patch("labwatch.scheduler.subprocess.run")
    def test_same_modules_replaces(self, mock_run, mock_path):
        stored, fake_run = _mock_crontab()
        mock_run.side_effect = fake_run

        add_entry("check", "1m", modules=["network"])
        add_entry("check", "5m", modules=["network"])  # change interval

        # Should only have one network entry
        lw_lines = [
            l for l in stored["content"].splitlines()
            if "labwatch:check:network" in l
        ]
        assert len(lw_lines) == 1
        assert "1-59/5 * * * *" in lw_lines[0]

    @patch("labwatch.scheduler.sys.platform", "linux")
    @patch("labwatch.scheduler.resolve_labwatch_path", return_value="/usr/bin/labwatch")
    @patch("labwatch.scheduler.subprocess.run")
    def test_global_and_per_module_coexist(self, mock_run, mock_path):
        stored, fake_run = _mock_crontab()
        mock_run.side_effect = fake_run

        add_entry("check", "5m")  # global
        add_entry("check", "1m", modules=["network"])  # per-module

        content = stored["content"]
        assert "# labwatch:check\n" in content or content.endswith("# labwatch:check")
        assert "# labwatch:check:network" in content

    # --- use_sudo tests ---

    @patch("labwatch.scheduler.sys.platform", "linux")
    @patch("labwatch.scheduler.resolve_labwatch_path", return_value="/usr/bin/labwatch")
    @patch("labwatch.scheduler.subprocess.run")
    def test_use_sudo_prefixes_command(self, mock_run, mock_path):
        stored, fake_run = _mock_crontab()
        mock_run.side_effect = fake_run

        line = add_entry("system-update", "1w", use_sudo=True)
        assert "sudo /usr/bin/labwatch system-update" in line
        assert "# labwatch:system-update" in line

    @patch("labwatch.scheduler.sys.platform", "linux")
    @patch("labwatch.scheduler.resolve_labwatch_path", return_value="/usr/bin/labwatch")
    @patch("labwatch.scheduler.subprocess.run")
    def test_use_sudo_false_no_prefix(self, mock_run, mock_path):
        stored, fake_run = _mock_crontab()
        mock_run.side_effect = fake_run

        line = add_entry("system-update", "1w", use_sudo=False)
        assert "sudo" not in line
        assert "/usr/bin/labwatch system-update" in line

    @patch("labwatch.scheduler.sys.platform", "linux")
    @patch("labwatch.scheduler.resolve_labwatch_path", return_value="/usr/bin/labwatch")
    @patch("labwatch.scheduler.subprocess.run")
    def test_use_sudo_with_modules(self, mock_run, mock_path):
        stored, fake_run = _mock_crontab()
        mock_run.side_effect = fake_run

        line = add_entry("check", "5m", modules=["network"], use_sudo=True)
        assert "sudo /usr/bin/labwatch check --only network" in line

    # --- Sentinel block tests ---

    @patch("labwatch.scheduler.sys.platform", "linux")
    @patch("labwatch.scheduler.resolve_labwatch_path", return_value="/usr/bin/labwatch")
    @patch("labwatch.scheduler.subprocess.run")
    def test_sentinel_block_created(self, mock_run, mock_path):
        stored, fake_run = _mock_crontab()
        mock_run.side_effect = fake_run

        add_entry("check", "5m")
        assert _SENTINEL_BEGIN in stored["content"]
        assert _SENTINEL_END in stored["content"]

    @patch("labwatch.scheduler.sys.platform", "linux")
    @patch("labwatch.scheduler.resolve_labwatch_path", return_value="/usr/bin/labwatch")
    @patch("labwatch.scheduler.subprocess.run")
    def test_user_entries_preserved_outside_block(self, mock_run, mock_path):
        existing = "0 * * * * /usr/bin/backup.sh\n"
        stored, fake_run = _mock_crontab(existing)
        mock_run.side_effect = fake_run

        add_entry("check", "5m")
        lines = stored["content"].splitlines()
        assert lines[0] == "0 * * * * /usr/bin/backup.sh"
        # Sentinel block should come after user entry
        begin_idx = lines.index(_SENTINEL_BEGIN)
        assert begin_idx > 0

    @patch("labwatch.scheduler.sys.platform", "linux")
    @patch("labwatch.scheduler.resolve_labwatch_path", return_value="/usr/bin/labwatch")
    @patch("labwatch.scheduler.subprocess.run")
    def test_legacy_entries_migrated_into_block(self, mock_run, mock_path):
        """Legacy labwatch entries (no sentinel) should be wrapped in block."""
        existing = (
            "0 * * * * /usr/bin/backup.sh\n"
            "*/5 * * * * /usr/bin/labwatch check # labwatch:check\n"
        )
        stored, fake_run = _mock_crontab(existing)
        mock_run.side_effect = fake_run

        add_entry("check", "1m", modules=["network"])

        content = stored["content"]
        lines = content.splitlines()
        # User entry stays outside
        assert lines[0] == "0 * * * * /usr/bin/backup.sh"
        # Both labwatch entries inside sentinel block
        assert _SENTINEL_BEGIN in content
        assert _SENTINEL_END in content
        begin_idx = lines.index(_SENTINEL_BEGIN)
        end_idx = lines.index(_SENTINEL_END)
        block = lines[begin_idx + 1:end_idx]
        assert len(block) == 2
        assert any("labwatch:check\n" in l or l.endswith("labwatch:check") for l in block)
        assert any("labwatch:check:network" in l for l in block)


# ---------------------------------------------------------------------------
# remove_entries
# ---------------------------------------------------------------------------

class TestRemoveEntries:

    @patch("labwatch.scheduler.sys.platform", "linux")
    @patch("labwatch.scheduler.subprocess.run")
    def test_remove_check_removes_all_variants(self, mock_run):
        existing = (
            f"0 * * * * /usr/bin/backup.sh\n"
            f"{_SENTINEL_BEGIN}\n"
            f"*/5 * * * * /usr/bin/labwatch check # labwatch:check\n"
            f"*/1 * * * * /usr/bin/labwatch check --only network # labwatch:check:network\n"
            f"0 0 * * * /usr/bin/labwatch docker-update # labwatch:docker-update\n"
            f"{_SENTINEL_END}\n"
        )
        stored, fake_run = _mock_crontab(existing)
        mock_run.side_effect = fake_run

        removed = remove_entries("check")
        assert removed == 2
        # docker-update should remain inside block, backup outside
        content = stored["content"]
        assert "backup" in content
        assert "docker-update" in content
        assert "labwatch:check:network" not in content
        assert _SENTINEL_BEGIN in content  # block still there for docker-update

    @patch("labwatch.scheduler.sys.platform", "linux")
    @patch("labwatch.scheduler.subprocess.run")
    def test_remove_all_removes_sentinel_block(self, mock_run):
        existing = (
            f"0 * * * * /usr/bin/backup.sh\n"
            f"{_SENTINEL_BEGIN}\n"
            f"*/5 * * * * /usr/bin/labwatch check # labwatch:check\n"
            f"{_SENTINEL_END}\n"
        )
        stored, fake_run = _mock_crontab(existing)
        mock_run.side_effect = fake_run

        removed = remove_entries()
        assert removed == 1
        content = stored["content"]
        assert "backup" in content
        assert _SENTINEL_BEGIN not in content
        assert _SENTINEL_END not in content


# ---------------------------------------------------------------------------
# list_entries
# ---------------------------------------------------------------------------

class TestListEntries:

    @patch("labwatch.scheduler.sys.platform", "linux")
    @patch("labwatch.scheduler.subprocess.run")
    def test_list_returns_only_labwatch_lines(self, mock_run):
        existing = (
            f"0 * * * * /usr/bin/backup.sh\n"
            f"{_SENTINEL_BEGIN}\n"
            f"*/5 * * * * /usr/bin/labwatch check # labwatch:check\n"
            f"*/1 * * * * /usr/bin/labwatch check --only network # labwatch:check:network\n"
            f"{_SENTINEL_END}\n"
        )
        stored, fake_run = _mock_crontab(existing)
        mock_run.side_effect = fake_run

        entries = list_entries()
        assert len(entries) == 2
        assert all("labwatch:" in e for e in entries)
        assert not any("backup" in e for e in entries)
