"""Read-only Cisco switch-port dashboard.
Credentials received by this process are transient and never persisted or logged.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import re
import socket
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

import paramiko
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

BASE_DIR = Path(__file__).resolve().parent
KNOWN_HOSTS = BASE_DIR / "known_hosts"
PORT_STATUSES = {"connected", "notconnect", "disabled", "err-disabled", "errdisable"}
COMMANDS = (
    "show interfaces status",
    "show interfaces description",
    "show mac address-table",
    "show logging | include %LINK-|%LINEPROTO-",
)
PROMPT_RE = re.compile(r"(?m)^[^\r\n]+[>#]\s*$")

app = FastAPI(title="Cisco Port Status Dashboard", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


class CiscoLegacyTransport(paramiko.Transport):
    """Permit older Cisco group14 SHA-1 KEX without preferring it."""

    def __init__(self, sock, *args, **kwargs):
        super().__init__(sock, *args, **kwargs)
        security = self.get_security_options()
        # Keep Paramiko's modern preference order. Remove group1 entirely and
        # retain/add only the legacy group14 SHA-1 option needed by older IOS.
        kex = [name for name in security.kex if name != "diffie-hellman-group1-sha1"]
        if "diffie-hellman-group14-sha1" not in kex:
            kex.append("diffie-hellman-group14-sha1")
        security.kex = tuple(kex)


class ConnectionRequest(BaseModel):
    host: str = Field(min_length=1, max_length=253)
    primary_username: str = Field(min_length=1, max_length=128)
    primary_password: str = Field(min_length=1, max_length=512)
    secondary_username: str = Field(default="", max_length=128)
    secondary_password: str = Field(default="", max_length=512)
    trust_fingerprint: str | None = Field(default=None, max_length=128)

    @field_validator("host")
    @classmethod
    def valid_host(cls, value: str) -> str:
        host = value.strip()
        if not host or any(c.isspace() for c in host) or "/" in host or "\\" in host:
            raise ValueError("Enter a valid IP address or hostname")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if not re.fullmatch(r"[A-Za-z0-9.-]+", host):
                raise ValueError("Enter a valid IP address or hostname")
        return host


class MacAddress(BaseModel):
    mac: str
    vlan: str
    entry_type: str


class LinkEvent(BaseModel):
    timestamp: str
    source: Literal["LINK", "LINEPROTO"]
    state: Literal["up", "down"]


class Port(BaseModel):
    interface: str
    name: str = ""
    status: str
    category: Literal["active", "disconnected", "disabled", "error", "unknown"]
    vlan: str = ""
    duplex: str = ""
    speed: str = ""
    media_type: str = ""
    description: str = ""
    mac_addresses: list[MacAddress] = Field(default_factory=list)
    link_events: list[LinkEvent] = Field(default_factory=list)


def fingerprint(key: paramiko.PKey) -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def category_for(status: str) -> str:
    normalized = status.lower()
    if normalized == "connected":
        return "active"
    if normalized == "notconnect":
        return "disconnected"
    if normalized == "disabled":
        return "disabled"
    if normalized in {"err-disabled", "errdisable"}:
        return "error"
    return "unknown"


def parse_interface_status(output: str) -> list[Port]:
    ports: list[Port] = []
    for raw_line in output.splitlines():
        line = raw_line.rstrip()
        if not line or line.lstrip().startswith(("Port ", "----", "Load for", "Time source")):
            continue
        match = re.match(
            r"^(?P<interface>\S+)\s*(?P<before>.*?)\s+(?P<status>connected|notconnect|disabled|err-disabled|errdisable)\b(?P<after>.*)$",
            line.strip(),
            flags=re.IGNORECASE,
        )
        if not match:
            continue
        interface = match.group("interface")
        name = match.group("before").strip()
        remaining = match.group("after").split()
        status = match.group("status").lower()
        ports.append(Port(
            interface=interface,
            name=name,
            status="err-disabled" if status == "errdisable" else status,
            category=category_for(status),
            vlan=remaining[0] if len(remaining) > 0 else "",
            duplex=remaining[1] if len(remaining) > 1 else "",
            speed=remaining[2] if len(remaining) > 2 else "",
            media_type=" ".join(remaining[3:]) if len(remaining) > 3 else "",
        ))
    return ports


def parse_descriptions(output: str) -> dict[str, str]:
    descriptions: dict[str, str] = {}
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or line.lower().startswith("interface") or set(line) == {"-"}:
            continue
        parts = re.split(r"\s{2,}", line, maxsplit=3)
        if len(parts) >= 4 and re.match(r"^[A-Za-z]+[\d/.-]+$", parts[0]):
            descriptions[parts[0]] = parts[3].strip()
    return descriptions


def parse_mac_address_table(output: str) -> dict[str, list[MacAddress]]:
    """Map conventional IOS/IOS-XE MAC-table records to their interface(s)."""
    by_interface: dict[str, list[MacAddress]] = {}
    pattern = re.compile(
        r"^\s*(?P<vlan>\S+)\s+(?P<mac>(?:[0-9A-Fa-f]{4}[.:]){2}[0-9A-Fa-f]{4})\s+"
        r"(?P<entry_type>\S+)\s+(?P<interfaces>\S+)\s*$"
    )
    for raw_line in output.splitlines():
        match = pattern.match(raw_line)
        if not match:
            continue
        entry = MacAddress(
            mac=match.group("mac").lower(),
            vlan=match.group("vlan"),
            entry_type=match.group("entry_type").lower(),
        )
        # IOS can list multiple output interfaces in one record; map each one.
        for interface in match.group("interfaces").split(","):
            interface = interface.strip()
            if interface and interface.lower() not in {"cpu", "router"}:
                by_interface.setdefault(interface, []).append(entry)
    return by_interface


def canonical_interface(interface: str) -> str:
    """Normalize long IOS interface names to the status-table abbreviations."""
    match = re.match(r"(?P<prefix>[A-Za-z-]+)(?P<suffix>[\d/.]+)$", interface.strip().rstrip(","))
    if not match:
        return interface.strip().rstrip(",")
    prefix = match.group("prefix").lower()
    abbreviations = {
        "gigabitethernet": "Gi", "gig": "Gi", "gi": "Gi",
        "fastethernet": "Fa", "fa": "Fa",
        "tengigabitethernet": "Te", "tengige": "Te", "te": "Te",
        "twentyfivegige": "Twe", "twe": "Twe",
        "fortygige": "Fo", "fo": "Fo",
        "hundredgige": "Hu", "hu": "Hu",
        "port-channel": "Po", "po": "Po",
    }
    return abbreviations.get(prefix, match.group("prefix")) + match.group("suffix")


def parse_link_events(output: str) -> dict[str, list[LinkEvent]]:
    """Read LINK/LINEPROTO transitions retained in the switch logging buffer."""
    by_interface: dict[str, list[LinkEvent]] = {}
    pattern = re.compile(
        r"^(?P<timestamp>.*?)%(?P<source>LINK|LINEPROTO)-\d+-UPDOWN:.*?"
        r"\bInterface\s+(?P<interface>[^,\s]+),\s+changed state to\s+(?P<state>up|down)\b",
        flags=re.IGNORECASE,
    )
    for raw_line in output.splitlines():
        match = pattern.search(raw_line)
        if not match:
            continue
        interface = canonical_interface(match.group("interface"))
        event = LinkEvent(
            timestamp=match.group("timestamp").strip().rstrip(":"),
            source=match.group("source").upper(),
            state=match.group("state").lower(),
        )
        by_interface.setdefault(interface, []).append(event)
    return by_interface


def unknown_host_response(host: str, port: int = 22) -> None:
    try:
        raw = socket.create_connection((host, port), timeout=8)
        transport = CiscoLegacyTransport(raw)
        transport.start_client(timeout=8)
        remote_key = transport.get_remote_server_key()
        key_fingerprint = fingerprint(remote_key)
        transport.close()
    except Exception as exc:
        raise HTTPException(status_code=502, detail="Unable to retrieve the switch SSH host key. Verify the address and network path.") from exc
    raise HTTPException(status_code=409, detail={
        "code": "unknown_host_key",
        "message": "Confirm this SSH host-key fingerprint before connecting.",
        "fingerprint": key_fingerprint,
    })


def add_known_host(host: str, expected_fingerprint: str) -> None:
    try:
        raw = socket.create_connection((host, 22), timeout=8)
        transport = CiscoLegacyTransport(raw)
        transport.start_client(timeout=8)
        key = transport.get_remote_server_key()
        observed = fingerprint(key)
        transport.close()
    except Exception as exc:
        raise HTTPException(status_code=502, detail="Unable to verify the switch SSH host key.") from exc
    if observed != expected_fingerprint:
        raise HTTPException(status_code=409, detail="SSH host key changed during confirmation; connection cancelled.")
    host_keys = paramiko.HostKeys()
    if KNOWN_HOSTS.exists():
        host_keys.load(str(KNOWN_HOSTS))
    host_keys.add(host, key.get_name(), key)
    host_keys.save(str(KNOWN_HOSTS))
    KNOWN_HOSTS.chmod(0o600)


def read_until_prompt(channel: paramiko.Channel, timeout: float = 25) -> str:
    """Read a Cisco interactive shell until its normal user/enable prompt."""
    chunks: list[bytes] = []
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if channel.recv_ready():
            chunk = channel.recv(65535)
            if not chunk:
                raise EOFError("Switch closed the SSH shell channel")
            chunks.append(chunk)
            text = b"".join(chunks).decode("utf-8", errors="replace").replace("\r", "")
            if PROMPT_RE.search(text):
                return text
        else:
            time.sleep(0.1)
    raise TimeoutError("Timed out waiting for the Cisco SSH prompt")


def collect(host: str, username: str, password: str) -> tuple[str, str, str, str]:
    client = paramiko.SSHClient()
    if KNOWN_HOSTS.exists():
        client.load_host_keys(str(KNOWN_HOSTS))
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect(
            hostname=host, port=22, username=username, password=password,
            timeout=10, banner_timeout=10, auth_timeout=10,
            look_for_keys=False, allow_agent=False,
            transport_factory=CiscoLegacyTransport,
        )
        # Older IOS SSH servers may close exec channels but support an
        # interactive shell. One shell also prevents command-by-command logins.
        channel = client.invoke_shell(width=200, height=1000)
        read_until_prompt(channel)
        channel.send("terminal length 0\n")
        read_until_prompt(channel)
        output: dict[str, str] = {}
        for command in COMMANDS:
            channel.send(command + "\n")
            output[command] = read_until_prompt(channel)
        return (
            output["show interfaces status"],
            output["show interfaces description"],
            output["show mac address-table"],
            output["show logging | include %LINK-|%LINEPROTO-"],
        )
    finally:
        client.close()


@app.get("/")
def root() -> FileResponse:
    return FileResponse(BASE_DIR / "static" / "index.html")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/connect")
def connect(request: ConnectionRequest) -> dict:
    # Passwords are used only during this request and deliberately never logged or persisted.
    if request.trust_fingerprint:
        add_known_host(request.host, request.trust_fingerprint)
    elif not KNOWN_HOSTS.exists() or request.host not in paramiko.HostKeys(str(KNOWN_HOSTS)):
        unknown_host_response(request.host)

    attempts = [("primary", request.primary_username, request.primary_password)]
    if request.secondary_username and request.secondary_password:
        attempts.append(("secondary", request.secondary_username, request.secondary_password))

    status_output = descriptions_output = mac_table_output = logging_output = None
    accepted_credential = None
    for label, username, password in attempts:
        try:
            status_output, descriptions_output, mac_table_output, logging_output = collect(request.host, username, password)
            accepted_credential = label
            break
        except paramiko.AuthenticationException:
            continue
        except paramiko.BadHostKeyException as exc:
            raise HTTPException(status_code=409, detail="SSH host key does not match the saved fingerprint; connection cancelled.") from exc
        except (paramiko.SSHException, OSError, socket.timeout, EOFError, TimeoutError) as exc:
            raise HTTPException(status_code=502, detail="SSH connection failed. Verify the address, SSH service, and network path.") from exc

    if status_output is None or descriptions_output is None or mac_table_output is None or logging_output is None:
        raise HTTPException(status_code=401, detail="Authentication failed with the supplied credentials.")

    descriptions = parse_descriptions(descriptions_output)
    mac_addresses = parse_mac_address_table(mac_table_output)
    link_events = parse_link_events(logging_output)
    ports = parse_interface_status(status_output)
    for port in ports:
        port.description = descriptions.get(port.interface, "")
        port.mac_addresses = mac_addresses.get(port.interface, [])
        port.link_events = link_events.get(canonical_interface(port.interface), [])
    counts = {category: sum(p.category == category for p in ports) for category in ("active", "disconnected", "disabled", "error", "unknown")}
    return {
        "host": request.host,
        "refreshed_at": datetime.now(timezone.utc).isoformat(),
        "accepted_credential": accepted_credential,
        "counts": counts,
        "ports": [port.model_dump() for port in ports],
    }
