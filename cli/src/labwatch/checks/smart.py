"""S.M.A.R.T. disk health checks for HDDs, SSDs, NVMe, and SD/eMMC."""

import json
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional

from labwatch.checks import BaseCheck, register
from labwatch.models import CheckResult, Severity


@register("smart")
class SmartCheck(BaseCheck):

    def run(self) -> List[CheckResult]:
        smart_cfg = self.config.get("checks", {}).get("smart", {})
        if not smart_cfg.get("enabled"):
            return []

        temp_warn = smart_cfg.get("temp_warning", 50)
        temp_crit = smart_cfg.get("temp_critical", 60)
        wear_warn = smart_cfg.get("wear_warning", 80)
        wear_crit = smart_cfg.get("wear_critical", 90)
        configured_devices = smart_cfg.get("devices", [])

        results = []

        # Check smartctl availability
        has_smartctl = shutil.which("smartctl") is not None

        if not has_smartctl and not self._has_mmc_devices():
            return [CheckResult(
                name="smart",
                severity=Severity.UNKNOWN,
                message=(
                    "smartctl not found. Install smartmontools: "
                    "apt install smartmontools / dnf install smartmontools"
                ),
            )]

        # Discover devices
        if configured_devices:
            devices = configured_devices
        else:
            devices = self._scan_devices(has_smartctl)

        if not devices:
            return [CheckResult(
                name="smart",
                severity=Severity.OK,
                message="No SMART-capable devices found",
            )]

        for device in devices:
            if device.startswith("/sys/block/mmcblk"):
                results.extend(self._check_mmc(device, wear_warn, wear_crit))
            elif has_smartctl:
                results.extend(self._check_smartctl(
                    device, temp_warn, temp_crit, wear_warn, wear_crit,
                ))

        return results

    def _has_mmc_devices(self) -> bool:
        """Check if any mmcblk devices exist in sysfs."""
        return bool(list(Path("/sys/block").glob("mmcblk*"))) if Path("/sys/block").exists() else False

    def _scan_devices(self, has_smartctl: bool) -> List[str]:
        """Discover SMART-capable devices."""
        devices = []

        # smartctl --scan for ATA/SCSI/NVMe
        if has_smartctl:
            try:
                result = subprocess.run(
                    ["smartctl", "--scan", "-j"],
                    capture_output=True, text=True, timeout=10,
                )
                if result.returncode == 0 or result.stdout.strip():
                    data = json.loads(result.stdout)
                    for dev in data.get("devices", []):
                        name = dev.get("name", "")
                        if name:
                            devices.append(name)
            except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
                pass

        # SD/eMMC via sysfs
        if Path("/sys/block").exists():
            for blk in sorted(Path("/sys/block").glob("mmcblk[0-9]*")):
                # Skip partition entries (mmcblk0p1, etc.)
                if "p" not in blk.name.replace("mmcblk", ""):
                    devices.append(f"/sys/block/{blk.name}")

        return devices

    def _check_smartctl(
        self, device: str,
        temp_warn: float, temp_crit: float,
        wear_warn: float, wear_crit: float,
    ) -> List[CheckResult]:
        """Run smartctl against a single device and parse results."""
        try:
            result = subprocess.run(
                ["smartctl", "-a", "-j", device],
                capture_output=True, text=True, timeout=30,
            )
        except subprocess.TimeoutExpired:
            return [CheckResult(
                name=f"smart:{device}",
                severity=Severity.UNKNOWN,
                message="smartctl timed out",
            )]
        except OSError as e:
            return [CheckResult(
                name=f"smart:{device}",
                severity=Severity.UNKNOWN,
                message=f"Failed to run smartctl: {e}",
            )]

        # smartctl returns non-zero for various reasons (bit mask).
        # We still try to parse JSON output.
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            # Permission denied or other errors
            stderr = result.stderr.strip()
            if "Permission denied" in (result.stderr or "") or "permission" in (result.stderr or "").lower():
                return [CheckResult(
                    name=f"smart:{device}",
                    severity=Severity.UNKNOWN,
                    message="Permission denied — try running as root or adding user to 'disk' group",
                )]
            return [CheckResult(
                name=f"smart:{device}",
                severity=Severity.UNKNOWN,
                message=f"Could not parse smartctl output for {device}",
                details=stderr[:200] if stderr else None,
            )]

        results = []
        dev_name = data.get("device", {}).get("name", device)
        model = data.get("model_name", "Unknown")
        short_name = Path(dev_name).name if "/" in dev_name else dev_name

        # Determine device type
        dev_type = self._detect_type(data)

        # Overall SMART health assessment
        smart_status = data.get("smart_status", {})
        passed = smart_status.get("passed")
        if passed is False:
            results.append(CheckResult(
                name=f"smart:{short_name}",
                severity=Severity.CRITICAL,
                message=f"SMART overall health FAILED — {model} ({dev_type})",
            ))
        elif passed is True:
            results.append(CheckResult(
                name=f"smart:{short_name}",
                severity=Severity.OK,
                message=f"SMART healthy — {model} ({dev_type})",
            ))

        # Temperature
        temp = data.get("temperature", {}).get("current")
        if temp is not None:
            if temp >= temp_crit:
                sev = Severity.CRITICAL
            elif temp >= temp_warn:
                sev = Severity.WARNING
            else:
                sev = Severity.OK
            results.append(CheckResult(
                name=f"smart:{short_name}:temp",
                severity=sev,
                message=f"{temp}°C",
            ))

        # Type-specific wear/health indicators
        if dev_type == "nvme":
            results.extend(self._check_nvme(data, short_name, wear_warn, wear_crit))
        elif dev_type == "ssd":
            results.extend(self._check_ssd(data, short_name, wear_warn, wear_crit))
        else:
            results.extend(self._check_hdd(data, short_name))

        return results

    def _detect_type(self, data: dict) -> str:
        """Detect whether device is NVMe, SSD, or HDD."""
        dev_type = data.get("device", {}).get("type", "")
        if dev_type == "nvme":
            return "nvme"
        rotation = data.get("rotation_rate")
        if rotation == 0:
            return "ssd"
        if rotation is not None and rotation > 0:
            return "hdd"
        # Fallback: check for NVMe-specific fields
        if "nvme_smart_health_information_log" in data:
            return "nvme"
        return "unknown"

    def _check_nvme(self, data: dict, name: str, wear_warn: float, wear_crit: float) -> List[CheckResult]:
        """Parse NVMe-specific health indicators."""
        results = []
        nvme_log = data.get("nvme_smart_health_information_log", {})

        pct_used = nvme_log.get("percentage_used")
        if pct_used is not None:
            if pct_used >= wear_crit:
                sev = Severity.CRITICAL
            elif pct_used >= wear_warn:
                sev = Severity.WARNING
            else:
                sev = Severity.OK
            results.append(CheckResult(
                name=f"smart:{name}:wear",
                severity=sev,
                message=f"{pct_used}% life used",
            ))

        spare = nvme_log.get("available_spare")
        spare_thresh = nvme_log.get("available_spare_threshold")
        if spare is not None:
            if spare_thresh is not None and spare <= spare_thresh:
                sev = Severity.CRITICAL
            elif spare <= 20:
                sev = Severity.WARNING
            else:
                sev = Severity.OK
            results.append(CheckResult(
                name=f"smart:{name}:spare",
                severity=sev,
                message=f"{spare}% spare capacity",
            ))

        errors = nvme_log.get("media_errors", 0)
        if errors > 0:
            results.append(CheckResult(
                name=f"smart:{name}:errors",
                severity=Severity.WARNING,
                message=f"{errors} media error(s)",
            ))

        return results

    def _check_ssd(self, data: dict, name: str, wear_warn: float, wear_crit: float) -> List[CheckResult]:
        """Parse SSD-specific SMART attributes."""
        results = []
        attrs = self._get_ata_attributes(data)

        # Look for wear indicator (various attribute IDs/names)
        wear_value = None
        for attr_name in ("Wear_Leveling_Count", "Media_Wearout_Indicator", "Percent_Lifetime_Remain"):
            attr = attrs.get(attr_name)
            if attr is not None:
                wear_value = attr.get("value")
                if attr_name == "Percent_Lifetime_Remain":
                    # This one counts down from 100
                    if wear_value is not None:
                        wear_value = 100 - wear_value
                break

        if wear_value is not None:
            if wear_value >= wear_crit:
                sev = Severity.CRITICAL
            elif wear_value >= wear_warn:
                sev = Severity.WARNING
            else:
                sev = Severity.OK
            results.append(CheckResult(
                name=f"smart:{name}:wear",
                severity=sev,
                message=f"{wear_value}% life used",
            ))

        # Reallocated sectors
        results.extend(self._check_reallocated(attrs, name))

        return results

    def _check_hdd(self, data: dict, name: str) -> List[CheckResult]:
        """Parse HDD-specific SMART attributes."""
        results = []
        attrs = self._get_ata_attributes(data)

        # Reallocated sectors
        results.extend(self._check_reallocated(attrs, name))

        # Spin retry count
        spin_retry = attrs.get("Spin_Retry_Count")
        if spin_retry is not None:
            raw = spin_retry.get("raw", {}).get("value", 0)
            if raw > 0:
                results.append(CheckResult(
                    name=f"smart:{name}:spin_retry",
                    severity=Severity.WARNING,
                    message=f"{raw} spin retry event(s)",
                ))

        # Current pending sectors
        pending = attrs.get("Current_Pending_Sector")
        if pending is not None:
            raw = pending.get("raw", {}).get("value", 0)
            if raw > 0:
                results.append(CheckResult(
                    name=f"smart:{name}:pending",
                    severity=Severity.WARNING,
                    message=f"{raw} pending sector(s)",
                ))

        return results

    def _check_reallocated(self, attrs: dict, name: str) -> List[CheckResult]:
        """Check reallocated sector count — common to SSDs and HDDs."""
        realloc = attrs.get("Reallocated_Sector_Ct")
        if realloc is None:
            return []
        raw = realloc.get("raw", {}).get("value", 0)
        if raw == 0:
            return []
        sev = Severity.CRITICAL if raw > 100 else Severity.WARNING
        return [CheckResult(
            name=f"smart:{name}:realloc",
            severity=sev,
            message=f"{raw} reallocated sector(s)",
        )]

    def _get_ata_attributes(self, data: dict) -> dict:
        """Extract ATA SMART attributes into a name-keyed dict."""
        table = data.get("ata_smart_attributes", {}).get("table", [])
        return {attr["name"]: attr for attr in table if "name" in attr}

    def _check_mmc(self, sysfs_path: str, wear_warn: float, wear_crit: float) -> List[CheckResult]:
        """Check SD/eMMC health via sysfs life_time and pre_eol_info."""
        results = []
        blk_name = Path(sysfs_path).name
        device_dir = Path(sysfs_path) / "device"

        # life_time: two hex values (SLC and MLC areas), e.g. "0x03 0x03"
        life_time_path = device_dir / "life_time"
        if life_time_path.exists():
            try:
                raw = life_time_path.read_text().strip()
                # Parse the worst (highest) of the two values
                values = [int(v, 16) for v in raw.split() if v.startswith("0x")]
                if values:
                    worst = max(values)
                    # 0x01=0-10%, 0x02=10-20%, ..., 0x0A=90-100%, 0x0B=exceeded
                    pct_used = worst * 10  # approximate midpoint
                    if worst >= 0x0B:
                        sev = Severity.CRITICAL
                        msg = f"eMMC life exceeded (level 0x{worst:02X})"
                    elif pct_used >= wear_crit:
                        sev = Severity.CRITICAL
                        msg = f"~{pct_used}% life used (level 0x{worst:02X})"
                    elif pct_used >= wear_warn:
                        sev = Severity.WARNING
                        msg = f"~{pct_used}% life used (level 0x{worst:02X})"
                    else:
                        sev = Severity.OK
                        msg = f"~{pct_used}% life used (level 0x{worst:02X})"
                    results.append(CheckResult(
                        name=f"smart:{blk_name}:life",
                        severity=sev,
                        message=msg,
                    ))
            except (ValueError, OSError):
                pass

        # pre_eol_info: single hex value
        eol_path = device_dir / "pre_eol_info"
        if eol_path.exists():
            try:
                raw = eol_path.read_text().strip()
                eol_val = int(raw, 16) if raw.startswith("0x") else int(raw)
                # 0x01=normal, 0x02=warning (consumed 80%), 0x03=urgent
                if eol_val >= 3:
                    results.append(CheckResult(
                        name=f"smart:{blk_name}:eol",
                        severity=Severity.CRITICAL,
                        message="eMMC pre-EOL status: URGENT — replacement recommended",
                    ))
                elif eol_val == 2:
                    results.append(CheckResult(
                        name=f"smart:{blk_name}:eol",
                        severity=Severity.WARNING,
                        message="eMMC pre-EOL status: WARNING — approaching end of life",
                    ))
                elif eol_val == 1:
                    results.append(CheckResult(
                        name=f"smart:{blk_name}:eol",
                        severity=Severity.OK,
                        message="eMMC pre-EOL status: normal",
                    ))
            except (ValueError, OSError):
                pass

        if not results:
            results.append(CheckResult(
                name=f"smart:{blk_name}",
                severity=Severity.UNKNOWN,
                message="Could not read eMMC health info from sysfs",
            ))

        return results
