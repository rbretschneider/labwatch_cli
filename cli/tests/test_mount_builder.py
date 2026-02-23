"""Tests for the mount builder module."""

import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock, call

import pytest
from click.testing import CliRunner
from rich.console import Console

from labwatch.mount_builder import (
    NasServer,
    MountShare,
    validate_ip,
    validate_server_name,
    validate_share_name,
    detect_existing_mount_units,
    generate_mount_unit,
    generate_override_conf,
    generate_credentials_file,
    generate_docker_override,
    install_shares,
    preview_shares,
    add_shares_to_config,
    run_mount_builder,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def server():
    return NasServer(ip="10.0.0.220", name="california")


@pytest.fixture
def cifs_share(server):
    return MountShare(server=server, share_name="Photos", mount_type="cifs")


@pytest.fixture
def nfs_share(server):
    return MountShare(server=server, share_name="Backups", mount_type="nfs")


# ---------------------------------------------------------------------------
# Data model properties
# ---------------------------------------------------------------------------

class TestMountShareProperties:

    def test_mount_point(self, cifs_share):
        assert cifs_share.mount_point == "/mnt/california_Photos"

    def test_unit_name(self, cifs_share):
        assert cifs_share.unit_name == "mnt-california_Photos.mount"

    def test_what_cifs(self, cifs_share):
        assert cifs_share.what == "//10.0.0.220/Photos"

    def test_what_nfs(self, nfs_share):
        assert nfs_share.what == "10.0.0.220:/Backups"

    def test_mount_point_different_server(self):
        srv = NasServer(ip="192.168.1.1", name="nas01")
        share = MountShare(server=srv, share_name="media", mount_type="nfs")
        assert share.mount_point == "/mnt/nas01_media"
        assert share.unit_name == "mnt-nas01_media.mount"
        assert share.what == "192.168.1.1:/media"


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

class TestValidateIP:

    def test_valid_ipv4(self):
        assert validate_ip("10.0.0.220") is True

    def test_valid_ipv6(self):
        assert validate_ip("::1") is True

    def test_invalid_ip(self):
        assert validate_ip("not.an.ip") is False

    def test_empty(self):
        assert validate_ip("") is False

    def test_hostname_rejected(self):
        assert validate_ip("myserver.local") is False


class TestValidateServerName:

    def test_valid(self):
        assert validate_server_name("california") is True
        assert validate_server_name("nas_01") is True
        assert validate_server_name("NAS2") is True

    def test_invalid_special_chars(self):
        assert validate_server_name("my-server") is False
        assert validate_server_name("nas.local") is False
        assert validate_server_name("foo bar") is False
        assert validate_server_name("") is False


class TestValidateShareName:

    def test_valid(self):
        assert validate_share_name("Photos") is True
        assert validate_share_name("backup_2024") is True

    def test_invalid(self):
        assert validate_share_name("My Share") is False
        assert validate_share_name("photos/2024") is False
        assert validate_share_name("") is False


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

class TestDetectExistingMountUnits:

    @patch("labwatch.mount_builder.Path.is_dir", return_value=True)
    @patch("labwatch.mount_builder.Path.glob")
    def test_finds_units(self, mock_glob, mock_is_dir):
        mock_glob.return_value = [
            Path("/etc/systemd/system/mnt-nas_Photos.mount"),
            Path("/etc/systemd/system/mnt-nas_Backups.mount"),
        ]
        result = detect_existing_mount_units()
        assert result == ["mnt-nas_Backups.mount", "mnt-nas_Photos.mount"]

    @patch("labwatch.mount_builder.Path.is_dir", return_value=False)
    def test_no_systemd_dir(self, mock_is_dir):
        result = detect_existing_mount_units()
        assert result == []

    @patch("labwatch.mount_builder.Path.is_dir", return_value=True)
    @patch("labwatch.mount_builder.Path.glob")
    def test_no_units(self, mock_glob, mock_is_dir):
        mock_glob.return_value = []
        result = detect_existing_mount_units()
        assert result == []


# ---------------------------------------------------------------------------
# Generation — CIFS
# ---------------------------------------------------------------------------

class TestGenerateMountUnit:

    def test_cifs(self, cifs_share):
        content = generate_mount_unit(cifs_share)
        assert "What=//10.0.0.220/Photos" in content
        assert "Where=/mnt/california_Photos" in content
        assert "Type=cifs" in content
        assert "WantedBy=multi-user.target" in content
        assert "Description=Mount Photos from california (10.0.0.220)" in content

    def test_nfs(self, nfs_share):
        content = generate_mount_unit(nfs_share)
        assert "What=10.0.0.220:/Backups" in content
        assert "Type=nfs" in content


class TestGenerateOverrideConf:

    def test_cifs_with_credentials(self, cifs_share):
        content = generate_override_conf(cifs_share, "/etc/samba/credentials_california")
        assert "credentials=/etc/samba/credentials_california,rw,_netdev" in content
        assert "After=network-online.target remote-fs-pre.target" in content
        assert "Requires=network-online.target" in content
        assert "StartLimitBurst=0" in content
        assert "TimeoutSec=60" in content

    def test_cifs_without_credentials(self, cifs_share):
        content = generate_override_conf(cifs_share)
        assert "Options=rw,_netdev" in content
        assert "credentials=" not in content

    def test_nfs(self, nfs_share):
        content = generate_override_conf(nfs_share)
        assert "Options=rw,_netdev,soft,timeo=150" in content


class TestGenerateCredentialsFile:

    def test_content(self):
        content = generate_credentials_file("admin", "s3cret")
        assert content == "username=admin\npassword=s3cret\n"


class TestGenerateDockerOverride:

    def test_single_unit(self):
        content = generate_docker_override(["mnt-nas_Photos.mount"])
        assert "After=mnt-nas_Photos.mount" in content
        assert "Requires=mnt-nas_Photos.mount" in content

    def test_multiple_units(self):
        units = ["mnt-nas_Photos.mount", "mnt-nas_Backups.mount"]
        content = generate_docker_override(units)
        assert "After=mnt-nas_Photos.mount mnt-nas_Backups.mount" in content
        assert "Requires=mnt-nas_Photos.mount mnt-nas_Backups.mount" in content


# ---------------------------------------------------------------------------
# Installation
# ---------------------------------------------------------------------------

class TestInstallShares:

    @patch("labwatch.mount_builder.subprocess.run")
    def test_installs_cifs_with_credentials(self, mock_run, cifs_share):
        mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
        console = Console(quiet=True)

        results = install_shares(
            [cifs_share],
            credentials={"california": ("admin", "secret")},
            console=console,
        )

        assert len(results) == 1
        assert results[0]["ok"] is True

        # Verify sudo calls were made
        calls = mock_run.call_args_list
        # Should include: mkdir /etc/samba, tee credentials, chmod,
        #   mkdir mount_point, tee .mount, mkdir override dir,
        #   tee override.conf, daemon-reload, enable --now
        assert any(
            "mkdir" in str(c) and "/etc/samba" in str(c)
            for c in calls
        )
        assert any(
            "daemon-reload" in str(c)
            for c in calls
        )
        assert any(
            "enable" in str(c) and "--now" in str(c)
            for c in calls
        )

    @patch("labwatch.mount_builder.subprocess.run")
    def test_installs_nfs_no_credentials(self, mock_run, nfs_share):
        mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
        console = Console(quiet=True)

        results = install_shares([nfs_share], console=console)

        assert len(results) == 1
        assert results[0]["ok"] is True

        # No credentials file should be written for NFS
        calls = mock_run.call_args_list
        assert not any(
            "/etc/samba" in str(c)
            for c in calls
        )

    @patch("labwatch.mount_builder.subprocess.run")
    def test_install_with_docker_override(self, mock_run, cifs_share):
        mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
        console = Console(quiet=True)

        results = install_shares(
            [cifs_share],
            docker_override=True,
            console=console,
        )

        assert results[0]["ok"] is True
        calls = mock_run.call_args_list
        assert any(
            "docker.service.d" in str(c)
            for c in calls
        )

    @patch("labwatch.mount_builder.subprocess.run")
    def test_sudo_write_failure(self, mock_run, cifs_share):
        def _side_effect(cmd, **kwargs):
            if cmd[0] == "sudo" and cmd[1] == "tee":
                return MagicMock(returncode=1, stderr="Permission denied", stdout="")
            return MagicMock(returncode=0, stderr="", stdout="")

        mock_run.side_effect = _side_effect
        console = Console(quiet=True)

        results = install_shares([cifs_share], console=console)
        assert len(results) == 1
        assert results[0]["ok"] is False

    @patch("labwatch.mount_builder.subprocess.run")
    def test_enable_failure(self, mock_run, cifs_share):
        def _side_effect(cmd, **kwargs):
            if "enable" in cmd:
                raise subprocess.CalledProcessError(1, cmd)
            if cmd[0] == "sudo" and cmd[1] == "tee":
                return MagicMock(returncode=0, stderr="", stdout="")
            return MagicMock(returncode=0, stderr="", stdout="")

        mock_run.side_effect = _side_effect
        mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
        console = Console(quiet=True)

        results = install_shares([cifs_share], console=console)
        assert results[0]["ok"] is False
        assert "systemctl enable" in results[0]["error"]


# ---------------------------------------------------------------------------
# Preview (dry-run)
# ---------------------------------------------------------------------------

class TestPreviewShares:

    @patch("labwatch.mount_builder.subprocess.run")
    def test_dry_run_no_subprocess_calls(self, mock_run, cifs_share):
        """preview_shares should never call subprocess."""
        console = Console(quiet=True)
        preview_shares(
            [cifs_share],
            credentials={"california": ("admin", "secret")},
            docker_override=True,
            console=console,
        )
        mock_run.assert_not_called()


# ---------------------------------------------------------------------------
# Config integration
# ---------------------------------------------------------------------------

class TestAddSharesToConfig:

    def test_adds_mounts(self, cifs_share, nfs_share):
        config = {}
        console = Console(quiet=True)
        add_shares_to_config(config, [cifs_share, nfs_share], console)

        mounts_cfg = config["checks"]["mounts"]
        assert mounts_cfg["enabled"] is True
        assert len(mounts_cfg["mounts"]) == 2
        paths = [m["path"] for m in mounts_cfg["mounts"]]
        assert "/mnt/california_Photos" in paths
        assert "/mnt/california_Backups" in paths

    def test_no_duplicates(self, cifs_share):
        config = {
            "checks": {
                "mounts": {
                    "enabled": True,
                    "mounts": [{"path": "/mnt/california_Photos", "severity": "critical"}],
                },
            },
        }
        console = Console(quiet=True)
        add_shares_to_config(config, [cifs_share], console)
        assert len(config["checks"]["mounts"]["mounts"]) == 1

    def test_merges_with_existing(self, cifs_share, nfs_share):
        config = {
            "checks": {
                "mounts": {
                    "enabled": True,
                    "mounts": [{"path": "/mnt/existing", "severity": "warning"}],
                },
            },
        }
        console = Console(quiet=True)
        add_shares_to_config(config, [cifs_share], console)
        assert len(config["checks"]["mounts"]["mounts"]) == 2


# ---------------------------------------------------------------------------
# CLI command
# ---------------------------------------------------------------------------

class TestCLICommand:

    @patch("labwatch.mount_builder.sys")
    def test_non_linux_exits_gracefully(self, mock_sys):
        mock_sys.platform = "win32"
        console = Console(quiet=True)
        # run_mount_builder should return without error on non-Linux
        run_mount_builder(config={}, dry_run=False)
        # If we get here, it didn't crash — that's the test

    def test_cli_invocation(self):
        """Test that the mount-builder command exists and is callable."""
        from labwatch.cli import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["mount-builder", "--help"])
        assert result.exit_code == 0
        assert "CIFS/NFS" in result.output


# ---------------------------------------------------------------------------
# Interactive wizard flow
# ---------------------------------------------------------------------------

class TestRunMountBuilder:

    @patch("labwatch.mount_builder.sys")
    def test_non_linux_message(self, mock_sys):
        """Non-linux prints a message and returns."""
        mock_sys.platform = "darwin"
        config = {}
        # Should not raise
        run_mount_builder(config)

    @patch("labwatch.mount_builder.detect_existing_mount_units", return_value=[])
    @patch("labwatch.mount_builder.click.confirm", return_value=False)
    @patch("labwatch.mount_builder.click.prompt")
    @patch("labwatch.mount_builder.sys")
    def test_dry_run_skips_install(self, mock_sys, mock_prompt, mock_confirm, mock_detect):
        """Dry run should not call install_shares."""
        mock_sys.platform = "linux"
        # Simulate: cifs type, one server, one share, then finish
        mock_prompt.side_effect = [
            "cifs",         # mount type
            "10.0.0.1",     # server IP
            "mynas",        # server name
            "",             # no more servers
            "data",         # share name
            "",             # no more shares
            "admin",        # username
            "secret",       # password
        ]

        with patch("labwatch.mount_builder.install_shares") as mock_install:
            with patch("labwatch.mount_builder.preview_shares"):
                run_mount_builder(config={}, dry_run=True)
            mock_install.assert_not_called()
