from __future__ import annotations

import base64
import configparser
import fcntl
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import time
import uuid
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from umat.cape_gateway.schemas import MachineResult, ProfileRequest

LABEL_PATTERN = re.compile(r"^umat-[a-z0-9-]{1,80}-[0-9a-f]{8}$")


class ProfileManagementError(RuntimeError):
    pass


@dataclass(frozen=True)
class CapeProfileConfiguration:
    cape_root: Path
    state_root: Path
    image_root: Path
    base_domain: str
    base_disk: Path
    base_windows_version: str
    network: str
    bridge: str
    host_ip: str
    snapshot: str
    address_start: int
    address_end: int
    allowed_templates: frozenset[str]


class CapeProfileManager:
    def __init__(self, configuration: CapeProfileConfiguration) -> None:
        self.configuration = configuration

    @classmethod
    def from_environment(cls) -> CapeProfileManager:
        return cls(
            CapeProfileConfiguration(
                cape_root=Path(os.environ.get("UMAT_CAPE_ROOT", "/opt/CAPEv2")),
                state_root=Path(
                    os.environ.get("UMAT_CAPE_PROFILE_STATE_ROOT", "/var/lib/umat-cape-profiles")
                ),
                image_root=Path(
                    os.environ.get(
                        "UMAT_CAPE_PROFILE_IMAGE_ROOT", "/var/lib/libvirt/images/winstdt/profiles"
                    )
                ),
                base_domain=os.environ.get("UMAT_CAPE_BASE_DOMAIN", "winstdt-win10-22h2"),
                base_disk=Path(
                    os.environ.get(
                        "UMAT_CAPE_BASE_DISK",
                        "/var/lib/libvirt/images/winstdt/winstdt-win10-22h2-golden.qcow2",
                    )
                ),
                base_windows_version=os.environ.get(
                    "UMAT_CAPE_BASE_WINDOWS_VERSION", "Windows 10 22H2"
                ),
                network=os.environ.get("UMAT_CAPE_NETWORK", "winstdt-isolated"),
                bridge=os.environ.get("UMAT_CAPE_BRIDGE", "virbr-winstdt"),
                host_ip=os.environ.get("UMAT_CAPE_HOST_IP", "10.66.0.1"),
                snapshot=os.environ.get("UMAT_CAPE_PROFILE_SNAPSHOT", "umat-profile-baseline-v1"),
                address_start=int(os.environ.get("UMAT_CAPE_ADDRESS_START", "120")),
                address_end=int(os.environ.get("UMAT_CAPE_ADDRESS_END", "199")),
                allowed_templates=frozenset(
                    value.strip()
                    for value in os.environ.get(
                        "UMAT_CAPE_ALLOWED_TEMPLATES", "win10-hardened,winstdt-win10-22h2"
                    ).split(",")
                    if value.strip()
                ),
            )
        )

    @contextmanager
    def _locked(self) -> Iterator[None]:
        self.configuration.state_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        lock_path = self.configuration.state_root / ".lock"
        with lock_path.open("a+b") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            yield

    def create(self, profile: ProfileRequest) -> MachineResult:
        with self._locked():
            return self._create_locked(profile)

    def _create_locked(self, profile: ProfileRequest) -> MachineResult:
        if profile.cape_template not in self.configuration.allowed_templates:
            raise ProfileManagementError("CAPE template is not approved by this deployment")
        if profile.windows_version != self.configuration.base_windows_version:
            raise ProfileManagementError(
                "requested Windows version does not match the selected deployment baseline"
            )
        state_path = self.configuration.state_root / f"{profile.profile_id}.json"
        if state_path.is_file():
            state = json.loads(state_path.read_text())
            return MachineResult(
                operation_id=uuid.UUID(str(state["operation_id"])),
                machine_label=str(state["label"]),
            )
        label = f"umat-{profile.name}-{profile.profile_id.replace('-', '')[:8]}"
        if not LABEL_PATTERN.fullmatch(label):
            raise ProfileManagementError("generated machine label is invalid")
        base_size = self._image_virtual_size_gib(self.configuration.base_disk)
        if profile.disk_gb < base_size:
            raise ProfileManagementError(
                f"requested disk is {profile.disk_gb} GiB but template requires at least {base_size} GiB; "
                "rebuild the VMCloak template from the licensed ISO for a smaller disk"
            )
        operation_id = str(uuid.uuid4())
        ip = self._allocate_ip()
        mac = self._mac(label)
        disk = self.configuration.image_root / f"{label}.qcow2"
        snapshot_disk = (
            self.configuration.image_root / f"{label}-{self.configuration.snapshot}.qcow2"
        )
        snapshot_memory = (
            self.configuration.image_root / f"{label}-{self.configuration.snapshot}.mem"
        )
        created_domain = False
        self.configuration.image_root.mkdir(parents=True, exist_ok=True, mode=0o750)
        os.chown(self.configuration.image_root, self._uid("libvirt-qemu"), self._gid("kvm"))
        self.configuration.image_root.chmod(0o750)
        reservation_added = False
        try:
            self._run(
                ["qemu-img", "convert", "-O", "qcow2", str(self.configuration.base_disk), str(disk)]
            )
            self._run(["qemu-img", "resize", str(disk), f"{profile.disk_gb}G"])
            os.chown(disk, self._uid("libvirt-qemu"), self._gid("kvm"))
            disk.chmod(0o640)
            xml = self._domain_xml(profile, label, mac, disk)
            with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as temporary:
                temporary.write(xml)
                xml_path = Path(temporary.name)
            try:
                self._run(["virsh", "-c", "qemu:///system", "define", str(xml_path)])
            finally:
                xml_path.unlink(missing_ok=True)
            created_domain = True
            self._run(
                [
                    "virsh",
                    "-c",
                    "qemu:///system",
                    "net-update",
                    self.configuration.network,
                    "add-last",
                    "ip-dhcp-host",
                    f"<host mac='{mac}' name='{label}' ip='{ip}'/>",
                    "--live",
                    "--config",
                ]
            )
            reservation_added = True
            self._run(["virsh", "-c", "qemu:///system", "start", label])
            self._customize_guest(ip, profile)
            self._run(
                [
                    "virsh",
                    "-c",
                    "qemu:///system",
                    "snapshot-create-as",
                    label,
                    self.configuration.snapshot,
                    "--description",
                    "UMAT CAPE profile baseline",
                    "--live",
                    "--atomic",
                    f"--memspec={snapshot_memory},snapshot=external",
                    f"--diskspec=sda,file={snapshot_disk},snapshot=external",
                ]
            )
            self._run(["virsh", "-c", "qemu:///system", "destroy", label])
            self._write_cape_machine(label, ip, profile)
            state = {
                "schema_version": "1.0",
                "operation_id": operation_id,
                "profile_id": profile.profile_id,
                "label": label,
                "ip": ip,
                "mac": mac,
                "disk": str(disk),
                "snapshot_disk": str(snapshot_disk),
                "snapshot_memory": str(snapshot_memory),
                "requested_profile": profile.model_dump(mode="json"),
            }
            self._atomic_json(state_path, state)
            return MachineResult(operation_id=uuid.UUID(operation_id), machine_label=label)
        except Exception:
            if created_domain:
                self._run(["virsh", "-c", "qemu:///system", "destroy", label], check=False)
                self._run(
                    ["virsh", "-c", "qemu:///system", "undefine", label, "--snapshots-metadata"],
                    check=False,
                )
            if reservation_added:
                self._run(
                    [
                        "virsh",
                        "-c",
                        "qemu:///system",
                        "net-update",
                        self.configuration.network,
                        "delete",
                        "ip-dhcp-host",
                        f"<host mac='{mac}' name='{label}' ip='{ip}'/>",
                        "--live",
                        "--config",
                    ],
                    check=False,
                )
            for path in (disk, snapshot_disk, snapshot_memory):
                path.unlink(missing_ok=True)
            raise

    def delete(self, label: str) -> MachineResult:
        if not LABEL_PATTERN.fullmatch(label):
            raise ProfileManagementError("machine label is outside the UMAT-managed namespace")
        with self._locked():
            states = list(self.configuration.state_root.glob("*.json"))
            state_path = next(
                (item for item in states if json.loads(item.read_text()).get("label") == label),
                None,
            )
            if state_path is None:
                raise ProfileManagementError("managed machine does not exist")
            state = json.loads(state_path.read_text())
            domain_state = self._capture(
                ["virsh", "-c", "qemu:///system", "domstate", label], check=False
            ).strip()
            if domain_state and domain_state != "shut off":
                raise ProfileManagementError("CAPE machine is running and cannot be deleted")
            if self._cape_machine_locked(label):
                raise ProfileManagementError("CAPE machine is assigned to an analysis")
            self._remove_cape_machine(label)
            self._run(
                ["virsh", "-c", "qemu:///system", "undefine", label, "--snapshots-metadata"],
                check=False,
            )
            self._run(
                [
                    "virsh",
                    "-c",
                    "qemu:///system",
                    "net-update",
                    self.configuration.network,
                    "delete",
                    "ip-dhcp-host",
                    f"<host mac='{state['mac']}' name='{label}' ip='{state['ip']}'/>",
                    "--live",
                    "--config",
                ],
                check=False,
            )
            for key in ("disk", "snapshot_disk", "snapshot_memory"):
                path = Path(str(state[key]))
                if (
                    path.parent != self.configuration.image_root
                    or not path.name.startswith(f"{label}-")
                    and path.name != f"{label}.qcow2"
                ):
                    raise ProfileManagementError("refusing to remove an unexpected profile path")
                path.unlink(missing_ok=True)
            state_path.unlink()
            return MachineResult(operation_id=uuid.uuid4(), machine_label=label)

    def _domain_xml(self, profile: ProfileRequest, label: str, mac: str, disk: Path) -> str:
        root = ET.fromstring(  # noqa: S314 - input is trusted local libvirt output
            self._capture(
                [
                    "virsh",
                    "-c",
                    "qemu:///system",
                    "dumpxml",
                    "--inactive",
                    self.configuration.base_domain,
                ]
            )
        )
        root.find("name").text = label  # type: ignore[union-attr]
        root.find("uuid").text = str(uuid.uuid4())  # type: ignore[union-attr]
        root.find("memory").text = str(profile.ram_mb * 1024)  # type: ignore[union-attr]
        root.find("currentMemory").text = str(profile.ram_mb * 1024)  # type: ignore[union-attr]
        root.find("vcpu").text = str(profile.vcpus)  # type: ignore[union-attr]
        topology = root.find("./cpu/topology")
        if topology is not None:
            topology.set("cores", str(profile.vcpus))
        source = root.find("./devices/disk[@device='disk']/source")
        if source is None:
            raise ProfileManagementError("base domain has no file-backed system disk")
        source.set("file", str(disk))
        disk_node = root.find("./devices/disk[@device='disk']")
        if disk_node is not None:
            for backing in list(disk_node.findall("backingStore")):
                disk_node.remove(backing)
        interface = root.find("./devices/interface/mac")
        if interface is None:
            raise ProfileManagementError("base domain has no network MAC")
        interface.set("address", mac)
        for entry in root.findall("./sysinfo/system/entry"):
            if entry.get("name") == "uuid":
                entry.text = root.find("uuid").text  # type: ignore[union-attr]
        return ET.tostring(root, encoding="unicode")

    def _customize_guest(self, ip: str, profile: ProfileRequest) -> None:
        base_url = f"http://{ip}:8000"
        deadline = time.monotonic() + 300
        environment: dict[str, Any] | None = None
        with httpx.Client(base_url=base_url, timeout=15, trust_env=False) as client:
            while time.monotonic() < deadline:
                try:
                    response = client.get("/environ")
                    response.raise_for_status()
                    environment = response.json().get("environ")
                    if isinstance(environment, dict):
                        break
                except (httpx.HTTPError, ValueError):
                    time.sleep(2)
            if not isinstance(environment, dict) or not environment.get("TEMP"):
                raise ProfileManagementError("CAPE guest agent did not become ready")
            encoded = base64.b64encode(
                json.dumps(profile.user_profile.model_dump(mode="json")).encode()
            ).decode()
            script = self._profile_script(encoded)
            destination = str(environment["TEMP"]) + r"\umat-profile.ps1"
            stored = client.post(
                "/store",
                data={"filepath": destination},
                files={"file": ("umat-profile.ps1", script.encode(), "text/plain")},
            )
            stored.raise_for_status()
            executed = client.post(
                "/execute",
                data={
                    "command": (
                        "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass "
                        f'-File "{destination}"'
                    )
                },
            )
            executed.raise_for_status()
            value = executed.json()
            if value.get("error"):
                raise ProfileManagementError(f"guest profile customization failed: {value}")

    @staticmethod
    def _profile_script(encoded_profile: str) -> str:
        return f"""$ErrorActionPreference = 'Stop'
$profileJson = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{encoded_profile}'))
$profile = $profileJson | ConvertFrom-Json
Set-TimeZone -Id $profile.timezone
Set-WinSystemLocale -SystemLocale $profile.locale
Set-Culture -CultureInfo $profile.locale
$installed = Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*, HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* -ErrorAction SilentlyContinue | Where-Object DisplayName | Select-Object -ExpandProperty DisplayName
foreach ($required in $profile.installed_software) {{
  if (-not ($installed | Where-Object {{ $_ -like "*$required*" }})) {{ throw "Required software is absent: $required" }}
}}
$current = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.Split('\\')[-1]
if ($current -ne $profile.username) {{ Rename-LocalUser -Name $current -NewName $profile.username }}
if ($profile.administrator) {{
  $members = Get-LocalGroupMember -Group 'Administrators' | Select-Object -ExpandProperty Name
  if (-not ($members | Where-Object {{ $_ -like "*\\$($profile.username)" }})) {{
    try {{ Add-LocalGroupMember -Group 'Administrators' -Member $profile.username -ErrorAction Stop }}
    catch {{ if ($_.Exception.Message -notmatch 'already a member') {{ throw }} }}
  }}
}} else {{
  $members = Get-LocalGroupMember -Group 'Administrators' | Select-Object -ExpandProperty Name
  if ($members | Where-Object {{ $_ -like "*\\$($profile.username)" }}) {{
    Remove-LocalGroupMember -Group 'Administrators' -Member $profile.username
  }}
}}
"""

    def _allocate_ip(self) -> str:
        used = {
            str(value.get("ip"))
            for path in self.configuration.state_root.glob("*.json")
            if isinstance((value := json.loads(path.read_text())), dict)
        }
        for final in range(self.configuration.address_start, self.configuration.address_end + 1):
            candidate = f"10.66.0.{final}"
            if candidate not in used:
                return candidate
        raise ProfileManagementError("CAPE profile address pool is exhausted")

    def _write_cape_machine(self, label: str, ip: str, profile: ProfileRequest) -> None:
        path = self.configuration.cape_root / "conf/kvm.conf"
        parser = configparser.ConfigParser()
        parser.read(path)
        machines = [
            item.strip() for item in parser.get("kvm", "machines").split(",") if item.strip()
        ]
        if label not in machines:
            machines.append(label)
        parser.set("kvm", "machines", ",".join(machines))
        parser[label] = {
            "label": label,
            "platform": "windows",
            "ip": ip,
            "tags": "win10,umat-profile",
            "snapshot": self.configuration.snapshot,
            "interface": self.configuration.bridge,
            "resultserver_ip": self.configuration.host_ip,
            "arch": profile.architecture,
            "reserved": "no",
        }
        self._cape_db("add", label, ip, profile.architecture)
        try:
            self._atomic_config(path, parser)
        except Exception:
            self._cape_db("delete", label, "", "x64")
            raise

    def _remove_cape_machine(self, label: str) -> None:
        self._cape_db("delete", label, "", "x64")
        path = self.configuration.cape_root / "conf/kvm.conf"
        parser = configparser.ConfigParser()
        parser.read(path)
        machines = [
            item.strip()
            for item in parser.get("kvm", "machines").split(",")
            if item.strip() != label
        ]
        parser.set("kvm", "machines", ",".join(machines))
        parser.remove_section(label)
        self._atomic_config(path, parser)

    def _cape_machine_locked(self, label: str) -> bool:
        output = self._cape_db("locked", label, "", "x64")
        return output.strip() == "true"

    def _cape_db(self, action: str, label: str, ip: str, architecture: str) -> str:
        script = """import json, sys
from lib.cuckoo.core.database import init_database
d = init_database(exists_ok=True)
action, label, ip, architecture, snapshot, interface, resultserver_ip = sys.argv[1:8]
machine = d.view_machine_by_label(label)
if action == "locked":
    print(json.dumps(bool(machine.locked) if machine else False))
elif action == "delete":
    if machine:
        d.delete_machine(label)
    d.session.commit()
elif action == "add":
    if not machine:
        d.add_machine(name=label, label=label, arch=architecture, ip=ip, platform="windows", tags="win10,umat-profile", interface=interface, snapshot=snapshot, resultserver_ip=resultserver_ip, resultserver_port=2042, reserved=False)
    d.session.commit()
else:
    raise SystemExit("unsupported CAPE database operation")
"""
        return self._capture(
            [
                "sudo",
                "-n",
                "-u",
                "cape",
                "/etc/poetry/bin/poetry",
                "run",
                "python",
                "-c",
                script,
                action,
                label,
                ip,
                architecture,
                self.configuration.snapshot,
                self.configuration.bridge,
                self.configuration.host_ip,
            ],
            cwd=self.configuration.cape_root,
        )

    @staticmethod
    def _mac(label: str) -> str:
        digest = hashlib.sha256(label.encode()).digest()
        return "52:54:00:" + ":".join(f"{value:02x}" for value in digest[:3])

    @staticmethod
    def _uid(name: str) -> int:
        import pwd

        return pwd.getpwnam(name).pw_uid

    @staticmethod
    def _gid(name: str) -> int:
        import grp

        return grp.getgrnam(name).gr_gid

    @staticmethod
    def _run(command: list[str], *, check: bool = True, cwd: Path | None = None) -> None:
        subprocess.run(command, check=check, cwd=cwd)  # noqa: S603

    @staticmethod
    def _capture(command: list[str], *, check: bool = True, cwd: Path | None = None) -> str:
        return subprocess.run(  # noqa: S603
            command, check=check, cwd=cwd, capture_output=True, text=True
        ).stdout

    @classmethod
    def _image_virtual_size_gib(cls, path: Path) -> int:
        value = json.loads(cls._capture(["qemu-img", "info", "--output=json", str(path)]))
        size = int(value["virtual-size"])
        return (size + 1024**3 - 1) // 1024**3

    @staticmethod
    def _atomic_json(path: Path, value: dict[str, Any]) -> None:
        temporary = path.with_suffix(f".{secrets.token_hex(8)}.tmp")
        temporary.write_text(json.dumps(value, indent=2) + "\n")
        temporary.chmod(0o600)
        temporary.replace(path)

    @staticmethod
    def _atomic_config(path: Path, parser: configparser.ConfigParser) -> None:
        descriptor, name = tempfile.mkstemp(prefix="umat-kvm-", suffix=".conf", dir=path.parent)
        try:
            with os.fdopen(descriptor, "w") as output:
                parser.write(output)
                output.flush()
                os.fsync(output.fileno())
            shutil.copymode(path, name)
            shutil.chown(name, user="cape", group="cape")
            os.replace(name, path)
        finally:
            Path(name).unlink(missing_ok=True)
