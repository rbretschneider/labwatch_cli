"""Tests for the S.M.A.R.T. disk health check module."""

import json
import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from labwatch.checks.smart import SmartCheck
from labwatch.models import Severity


def _cfg(smart_cfg=None, enabled=True):
    base = {
        "enabled": enabled,
        "temp_warning": 50,
        "temp_critical": 60,
        "wear_warning": 80,
        "wear_critical": 90,
        "devices": [],
    }
    if smart_cfg:
        base.update(smart_cfg)
    return {"checks": {"smart": base}}


# ---------------------------------------------------------------------------
# smartctl not installed
# ---------------------------------------------------------------------------

class TestSmartctlNotInstalled:
    @patch("labwatch.checks.smart.shutil.which", return_value=None)
    @patch("labwatch.checks.smart.Path.exists", return_value=False)
    def test_returns_unknown_with_install_hint(self, mock_exists, mock_which):
        check = SmartCheck(_cfg())
        results = check.run()
        assert len(results) == 1
        assert results[0].severity == Severity.UNKNOWN
        assert "smartmontools" in results[0].message


# ---------------------------------------------------------------------------
# Disabled check
# ---------------------------------------------------------------------------

class TestSmartDisabled:
    def test_disabled_returns_empty(self):
        check = SmartCheck(_cfg(enabled=False))
        results = check.run()
        assert results == []


# ---------------------------------------------------------------------------
# Device scanning
# ---------------------------------------------------------------------------

class TestDeviceScanning:
    @patch("labwatch.checks.smart.shutil.which", return_value="/usr/sbin/smartctl")
    @patch("labwatch.checks.smart.subprocess.run")
    @patch("labwatch.checks.smart.Path.exists", return_value=False)
    def test_scan_discovers_devices(self, mock_exists, mock_run, mock_which):
        # smartctl --scan returns two devices
        scan_output = json.dumps({
            "devices": [
                {"name": "/dev/sda", "type": "sat"},
                {"name": "/dev/nvme0", "type": "nvme"},
            ]
        })
        mock_run.return_value = MagicMock(returncode=0, stdout=scan_output)

        check = SmartCheck(_cfg())
        devices = check._scan_devices(smartctl_path="/usr/sbin/smartctl")
        assert "/dev/sda" in devices
        assert "/dev/nvme0" in devices

    @patch("labwatch.checks.smart.shutil.which", return_value="/usr/sbin/smartctl")
    @patch("labwatch.checks.smart.subprocess.run")
    def test_scan_handles_timeout(self, mock_run, mock_which):
        mock_run.side_effect = subprocess.TimeoutExpired("smartctl", 10)
        check = SmartCheck(_cfg())
        devices = check._scan_devices(smartctl_path="/usr/sbin/smartctl")
        assert devices == []

    @patch("labwatch.checks.smart.shutil.which", return_value="/usr/sbin/smartctl")
    @patch("labwatch.checks.smart.subprocess.run")
    def test_scan_handles_invalid_json(self, mock_run, mock_which):
        mock_run.return_value = MagicMock(returncode=0, stdout="not json")
        check = SmartCheck(_cfg())
        devices = check._scan_devices(smartctl_path="/usr/sbin/smartctl")
        assert devices == []


# ---------------------------------------------------------------------------
# No devices found
# ---------------------------------------------------------------------------

class TestNoDevices:
    @patch("labwatch.checks.smart.shutil.which", return_value="/usr/sbin/smartctl")
    @patch("labwatch.checks.smart.subprocess.run")
    @patch("labwatch.checks.smart.Path.exists", return_value=False)
    def test_no_devices_returns_ok(self, mock_exists, mock_run, mock_which):
        scan_output = json.dumps({"devices": []})
        mock_run.return_value = MagicMock(returncode=0, stdout=scan_output)
        check = SmartCheck(_cfg())
        results = check.run()
        assert len(results) == 1
        assert results[0].severity == Severity.OK
        assert "No SMART-capable devices" in results[0].message


# ---------------------------------------------------------------------------
# smartctl device checks — NVMe
# ---------------------------------------------------------------------------

NVME_HEALTHY = json.dumps({
    "device": {"name": "/dev/nvme0", "type": "nvme"},
    "model_name": "Samsung 970 EVO Plus",
    "smart_status": {"passed": True},
    "temperature": {"current": 35},
    "nvme_smart_health_information_log": {
        "percentage_used": 5,
        "available_spare": 100,
        "available_spare_threshold": 10,
        "media_errors": 0,
    },
})

NVME_FAILING = json.dumps({
    "device": {"name": "/dev/nvme0", "type": "nvme"},
    "model_name": "Samsung 970 EVO Plus",
    "smart_status": {"passed": False},
    "temperature": {"current": 65},
    "nvme_smart_health_information_log": {
        "percentage_used": 95,
        "available_spare": 5,
        "available_spare_threshold": 10,
        "media_errors": 3,
    },
})


class TestNvmeCheck:
    def _run_with_output(self, stdout, **cfg_overrides):
        """Helper to run SmartCheck with a single device and mocked smartctl output."""
        with patch("labwatch.checks.smart.shutil.which", return_value="/usr/sbin/smartctl"), \
             patch("labwatch.checks.smart.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=stdout, stderr="")
            cfg = _cfg({"devices": ["/dev/nvme0"], **cfg_overrides})
            check = SmartCheck(cfg)
            return check.run()

    def test_healthy_nvme(self):
        results = self._run_with_output(NVME_HEALTHY)
        health = next(r for r in results if r.name == "smart:nvme0")
        assert health.severity == Severity.OK
        assert "healthy" in health.message

        temp = next(r for r in results if r.name == "smart:nvme0:temp")
        assert temp.severity == Severity.OK
        assert "35" in temp.message

        wear = next(r for r in results if r.name == "smart:nvme0:wear")
        assert wear.severity == Severity.OK
        assert "5%" in wear.message

        spare = next(r for r in results if r.name == "smart:nvme0:spare")
        assert spare.severity == Severity.OK

    def test_failing_nvme(self):
        results = self._run_with_output(NVME_FAILING)
        health = next(r for r in results if r.name == "smart:nvme0")
        assert health.severity == Severity.CRITICAL
        assert "FAILED" in health.message

        temp = next(r for r in results if r.name == "smart:nvme0:temp")
        assert temp.severity == Severity.CRITICAL

        wear = next(r for r in results if r.name == "smart:nvme0:wear")
        assert wear.severity == Severity.CRITICAL

        spare = next(r for r in results if r.name == "smart:nvme0:spare")
        assert spare.severity == Severity.CRITICAL

    def test_nvme_media_errors_warning(self):
        results = self._run_with_output(NVME_FAILING)
        errors = next(r for r in results if r.name == "smart:nvme0:errors")
        assert errors.severity == Severity.WARNING
        assert "3 media error" in errors.message

    def test_temp_warning_threshold(self):
        data = json.loads(NVME_HEALTHY)
        data["temperature"]["current"] = 55
        results = self._run_with_output(json.dumps(data))
        temp = next(r for r in results if r.name == "smart:nvme0:temp")
        assert temp.severity == Severity.WARNING

    def test_wear_warning_threshold(self):
        data = json.loads(NVME_HEALTHY)
        data["nvme_smart_health_information_log"]["percentage_used"] = 85
        results = self._run_with_output(json.dumps(data))
        wear = next(r for r in results if r.name == "smart:nvme0:wear")
        assert wear.severity == Severity.WARNING


# ---------------------------------------------------------------------------
# smartctl device checks — SSD (ATA)
# ---------------------------------------------------------------------------

SSD_HEALTHY = json.dumps({
    "device": {"name": "/dev/sda", "type": "sat"},
    "model_name": "Samsung 860 EVO",
    "rotation_rate": 0,
    "smart_status": {"passed": True},
    "temperature": {"current": 30},
    "ata_smart_attributes": {
        "table": [
            {"name": "Wear_Leveling_Count", "value": 10, "raw": {"value": 10}},
            {"name": "Reallocated_Sector_Ct", "value": 100, "raw": {"value": 0}},
        ]
    },
})

SSD_WORN = json.dumps({
    "device": {"name": "/dev/sda", "type": "sat"},
    "model_name": "Samsung 860 EVO",
    "rotation_rate": 0,
    "smart_status": {"passed": True},
    "temperature": {"current": 42},
    "ata_smart_attributes": {
        "table": [
            {"name": "Wear_Leveling_Count", "value": 92, "raw": {"value": 92}},
            {"name": "Reallocated_Sector_Ct", "value": 100, "raw": {"value": 5}},
        ]
    },
})


class TestSsdCheck:
    def _run_with_output(self, stdout, **cfg_overrides):
        with patch("labwatch.checks.smart.shutil.which", return_value="/usr/sbin/smartctl"), \
             patch("labwatch.checks.smart.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=stdout, stderr="")
            cfg = _cfg({"devices": ["/dev/sda"], **cfg_overrides})
            check = SmartCheck(cfg)
            return check.run()

    def test_healthy_ssd(self):
        results = self._run_with_output(SSD_HEALTHY)
        health = next(r for r in results if r.name == "smart:sda")
        assert health.severity == Severity.OK

        wear = next(r for r in results if r.name == "smart:sda:wear")
        assert wear.severity == Severity.OK

    def test_worn_ssd_with_reallocated_sectors(self):
        results = self._run_with_output(SSD_WORN)
        wear = next(r for r in results if r.name == "smart:sda:wear")
        assert wear.severity == Severity.CRITICAL

        realloc = next(r for r in results if r.name == "smart:sda:realloc")
        assert realloc.severity == Severity.WARNING
        assert "5 reallocated" in realloc.message

    def test_many_reallocated_sectors_critical(self):
        data = json.loads(SSD_WORN)
        for attr in data["ata_smart_attributes"]["table"]:
            if attr["name"] == "Reallocated_Sector_Ct":
                attr["raw"]["value"] = 200
        results = self._run_with_output(json.dumps(data))
        realloc = next(r for r in results if r.name == "smart:sda:realloc")
        assert realloc.severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# smartctl device checks — HDD
# ---------------------------------------------------------------------------

HDD_HEALTHY = json.dumps({
    "device": {"name": "/dev/sdb", "type": "sat"},
    "model_name": "WDC WD40EFRX",
    "rotation_rate": 5400,
    "smart_status": {"passed": True},
    "temperature": {"current": 32},
    "ata_smart_attributes": {
        "table": [
            {"name": "Reallocated_Sector_Ct", "value": 100, "raw": {"value": 0}},
            {"name": "Spin_Retry_Count", "value": 100, "raw": {"value": 0}},
            {"name": "Current_Pending_Sector", "value": 100, "raw": {"value": 0}},
        ]
    },
})

HDD_DEGRADED = json.dumps({
    "device": {"name": "/dev/sdb", "type": "sat"},
    "model_name": "WDC WD40EFRX",
    "rotation_rate": 5400,
    "smart_status": {"passed": True},
    "temperature": {"current": 32},
    "ata_smart_attributes": {
        "table": [
            {"name": "Reallocated_Sector_Ct", "value": 100, "raw": {"value": 3}},
            {"name": "Spin_Retry_Count", "value": 100, "raw": {"value": 2}},
            {"name": "Current_Pending_Sector", "value": 100, "raw": {"value": 1}},
        ]
    },
})


class TestHddCheck:
    def _run_with_output(self, stdout):
        with patch("labwatch.checks.smart.shutil.which", return_value="/usr/sbin/smartctl"), \
             patch("labwatch.checks.smart.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=stdout, stderr="")
            cfg = _cfg({"devices": ["/dev/sdb"]})
            check = SmartCheck(cfg)
            return check.run()

    def test_healthy_hdd(self):
        results = self._run_with_output(HDD_HEALTHY)
        health = next(r for r in results if r.name == "smart:sdb")
        assert health.severity == Severity.OK
        # No reallocated/spin_retry/pending results when all are zero
        names = [r.name for r in results]
        assert "smart:sdb:realloc" not in names
        assert "smart:sdb:spin_retry" not in names
        assert "smart:sdb:pending" not in names

    def test_degraded_hdd(self):
        results = self._run_with_output(HDD_DEGRADED)
        realloc = next(r for r in results if r.name == "smart:sdb:realloc")
        assert realloc.severity == Severity.WARNING

        spin = next(r for r in results if r.name == "smart:sdb:spin_retry")
        assert spin.severity == Severity.WARNING
        assert "2 spin retry" in spin.message

        pending = next(r for r in results if r.name == "smart:sdb:pending")
        assert pending.severity == Severity.WARNING
        assert "1 pending" in pending.message


# ---------------------------------------------------------------------------
# smartctl error handling
# ---------------------------------------------------------------------------

class TestSmartctlErrors:
    def test_smartctl_timeout(self):
        with patch("labwatch.checks.smart.shutil.which", return_value="/usr/sbin/smartctl"), \
             patch("labwatch.checks.smart.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired("smartctl", 30)
            cfg = _cfg({"devices": ["/dev/sda"]})
            check = SmartCheck(cfg)
            results = check.run()
            assert len(results) == 1
            assert results[0].severity == Severity.UNKNOWN
            assert "timed out" in results[0].message

    def test_smartctl_permission_denied(self):
        with patch("labwatch.checks.smart.shutil.which", return_value="/usr/sbin/smartctl"), \
             patch("labwatch.checks.smart.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=2, stdout="", stderr="Permission denied",
            )
            cfg = _cfg({"devices": ["/dev/sda"]})
            check = SmartCheck(cfg)
            results = check.run()
            assert len(results) == 1
            assert results[0].severity == Severity.UNKNOWN
            assert "Permission denied" in results[0].message

    def test_smartctl_invalid_json(self):
        with patch("labwatch.checks.smart.shutil.which", return_value="/usr/sbin/smartctl"), \
             patch("labwatch.checks.smart.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1, stdout="garbage", stderr="some error",
            )
            cfg = _cfg({"devices": ["/dev/sda"]})
            check = SmartCheck(cfg)
            results = check.run()
            assert len(results) == 1
            assert results[0].severity == Severity.UNKNOWN

    def test_smartctl_oserror(self):
        with patch("labwatch.checks.smart.shutil.which", return_value="/usr/sbin/smartctl"), \
             patch("labwatch.checks.smart.subprocess.run") as mock_run:
            mock_run.side_effect = OSError("something went wrong")
            cfg = _cfg({"devices": ["/dev/sda"]})
            check = SmartCheck(cfg)
            results = check.run()
            assert len(results) == 1
            assert results[0].severity == Severity.UNKNOWN
            assert "Failed to run smartctl" in results[0].message


# ---------------------------------------------------------------------------
# Device type detection
# ---------------------------------------------------------------------------

class TestDeviceTypeDetection:
    def test_detect_nvme(self):
        check = SmartCheck(_cfg())
        assert check._detect_type({"device": {"type": "nvme"}}) == "nvme"

    def test_detect_ssd(self):
        check = SmartCheck(_cfg())
        assert check._detect_type({"device": {"type": "sat"}, "rotation_rate": 0}) == "ssd"

    def test_detect_hdd(self):
        check = SmartCheck(_cfg())
        assert check._detect_type({"device": {"type": "sat"}, "rotation_rate": 7200}) == "hdd"

    def test_detect_nvme_via_log(self):
        check = SmartCheck(_cfg())
        result = check._detect_type({
            "device": {"type": ""},
            "nvme_smart_health_information_log": {},
        })
        assert result == "nvme"

    def test_detect_unknown(self):
        check = SmartCheck(_cfg())
        assert check._detect_type({"device": {"type": ""}}) == "unknown"


# ---------------------------------------------------------------------------
# SD/eMMC via sysfs
# ---------------------------------------------------------------------------

class TestMmcCheck:
    def test_healthy_mmc(self, tmp_path):
        """life_time 0x02 (10-20% used) -> OK."""
        blk = tmp_path / "mmcblk0"
        blk.mkdir()
        device_dir = blk / "device"
        device_dir.mkdir()
        (device_dir / "life_time").write_text("0x02 0x02\n")
        (device_dir / "pre_eol_info").write_text("0x01\n")

        check = SmartCheck(_cfg())
        results = check._check_mmc(str(blk), wear_warn=80, wear_crit=90)

        life = next(r for r in results if "life" in r.name)
        assert life.severity == Severity.OK
        assert "20%" in life.message

        eol = next(r for r in results if "eol" in r.name)
        assert eol.severity == Severity.OK
        assert "normal" in eol.message

    def test_worn_mmc(self, tmp_path):
        """life_time 0x08 (70-80% used) -> WARNING with default thresholds."""
        blk = tmp_path / "mmcblk0"
        blk.mkdir()
        device_dir = blk / "device"
        device_dir.mkdir()
        (device_dir / "life_time").write_text("0x08 0x07\n")

        check = SmartCheck(_cfg())
        results = check._check_mmc(str(blk), wear_warn=80, wear_crit=90)

        life = next(r for r in results if "life" in r.name)
        assert life.severity == Severity.WARNING

    def test_critical_mmc(self, tmp_path):
        """life_time 0x0B (exceeded) -> CRITICAL."""
        blk = tmp_path / "mmcblk0"
        blk.mkdir()
        device_dir = blk / "device"
        device_dir.mkdir()
        (device_dir / "life_time").write_text("0x0B 0x0A\n")

        check = SmartCheck(_cfg())
        results = check._check_mmc(str(blk), wear_warn=80, wear_crit=90)

        life = next(r for r in results if "life" in r.name)
        assert life.severity == Severity.CRITICAL
        assert "exceeded" in life.message

    def test_eol_warning(self, tmp_path):
        """pre_eol_info 0x02 -> WARNING."""
        blk = tmp_path / "mmcblk0"
        blk.mkdir()
        device_dir = blk / "device"
        device_dir.mkdir()
        (device_dir / "pre_eol_info").write_text("0x02\n")

        check = SmartCheck(_cfg())
        results = check._check_mmc(str(blk), wear_warn=80, wear_crit=90)

        eol = next(r for r in results if "eol" in r.name)
        assert eol.severity == Severity.WARNING

    def test_eol_urgent(self, tmp_path):
        """pre_eol_info 0x03 -> CRITICAL."""
        blk = tmp_path / "mmcblk0"
        blk.mkdir()
        device_dir = blk / "device"
        device_dir.mkdir()
        (device_dir / "pre_eol_info").write_text("0x03\n")

        check = SmartCheck(_cfg())
        results = check._check_mmc(str(blk), wear_warn=80, wear_crit=90)

        eol = next(r for r in results if "eol" in r.name)
        assert eol.severity == Severity.CRITICAL

    def test_no_sysfs_files(self, tmp_path):
        """No life_time or pre_eol_info -> UNKNOWN."""
        blk = tmp_path / "mmcblk0"
        blk.mkdir()
        device_dir = blk / "device"
        device_dir.mkdir()

        check = SmartCheck(_cfg())
        results = check._check_mmc(str(blk), wear_warn=80, wear_crit=90)

        assert len(results) == 1
        assert results[0].severity == Severity.UNKNOWN


# ---------------------------------------------------------------------------
# Configured devices override auto-detect
# ---------------------------------------------------------------------------

class TestConfiguredDevices:
    def test_uses_configured_devices(self):
        with patch("labwatch.checks.smart.shutil.which", return_value="/usr/sbin/smartctl"), \
             patch("labwatch.checks.smart.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout=NVME_HEALTHY, stderr="",
            )
            cfg = _cfg({"devices": ["/dev/nvme0"]})
            check = SmartCheck(cfg)
            results = check.run()
            # Should NOT call --scan since devices are configured
            calls = [str(c) for c in mock_run.call_args_list]
            assert not any("--scan" in c for c in calls)
            # Should have results from the configured device
            assert any(r.name == "smart:nvme0" for r in results)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

class TestSmartRegistration:
    def test_smart_in_registry(self):
        from labwatch.checks import get_check_classes
        classes = get_check_classes()
        assert "smart" in classes
        assert classes["smart"] is SmartCheck
