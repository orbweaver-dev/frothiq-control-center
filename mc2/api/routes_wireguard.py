"""
ServOps — WireGuard VPN management API (super_admin only).
Handles interface lifecycle, peer management, key generation, and raw config editing.
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator

from .routes_auth import require_super_admin

router = APIRouter(prefix="/sysinfo/wireguard", tags=["wireguard"])

WG_DIR = Path("/etc/wireguard")

# WireGuard key regex (base64, 44 chars)
_KEY_RE = re.compile(r'^[A-Za-z0-9+/]{43}=$')


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(cmd: list[str], timeout: int = 15) -> tuple[str, str, int]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", f"Timeout after {timeout}s", 1
    except Exception as e:
        return "", str(e), 1


def _wg_available() -> bool:
    _, _, rc = _run(["which", "wg"], timeout=3)
    return rc == 0


def _wg_status() -> dict[str, dict]:
    """Parse `sudo wg show all dump` → {iface: {public_key, listen_port, running, peers: [...]}}"""
    out, _, rc = _run(["sudo", "wg", "show", "all", "dump"], timeout=8)
    status: dict[str, dict] = {}
    if rc != 0:
        return status
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) == 5:
            # Interface line: iface, private_key, public_key, listen_port, fwmark
            iface = parts[0]
            status.setdefault(iface, {"public_key": "", "listen_port": "", "running": True, "live_peers": []})
            status[iface]["public_key"] = parts[2]
            status[iface]["listen_port"] = parts[3]
        elif len(parts) == 9:
            # Peer line: iface, pubkey, preshared, endpoint, allowed_ips, last_handshake, rx, tx, keepalive
            iface = parts[0]
            status.setdefault(iface, {"public_key": "", "listen_port": "", "running": True, "live_peers": []})
            last_hs = int(parts[5]) if parts[5].isdigit() else 0
            status[iface]["live_peers"].append({
                "public_key": parts[1],
                "endpoint": parts[3] if parts[3] != "(none)" else "",
                "allowed_ips": parts[4],
                "last_handshake": last_hs,
                "rx_bytes": int(parts[6]) if parts[6].isdigit() else 0,
                "tx_bytes": int(parts[7]) if parts[7].isdigit() else 0,
            })
    return status


def _parse_conf(path: Path) -> dict:
    """Parse a WireGuard .conf file into {interface: {}, peers: []}."""
    interface: dict[str, str] = {}
    peers: list[dict] = []
    current_peer: dict | None = None
    pending_name: str | None = None

    for raw in path.read_text(errors="replace").splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#"):
            m = re.match(r"#\s*(?:Name|name)[:=]\s*(.+)", line)
            if m:
                pending_name = m.group(1).strip()
            continue
        if line.lower() == "[interface]":
            current_peer = None
            continue
        if line.lower() == "[peer]":
            if current_peer is not None:
                peers.append(current_peer)
            current_peer = {"name": pending_name or ""}
            pending_name = None
            continue
        if "=" in line:
            k, _, v = line.partition("=")
            k, v = k.strip(), v.strip()
            if current_peer is not None:
                current_peer[k] = v
            else:
                interface[k] = v

    if current_peer is not None:
        peers.append(current_peer)

    return {"interface": interface, "peers": peers}


def _build_conf(interface: dict, peers: list[dict]) -> str:
    """Serialise structured data back to WireGuard .conf format."""
    lines = ["[Interface]"]
    key_order = ["Address", "ListenPort", "PrivateKey", "DNS", "MTU",
                 "Table", "PreUp", "PostUp", "PreDown", "PostDown"]
    written = set()
    for k in key_order:
        if interface.get(k):
            lines.append(f"{k} = {interface[k]}")
            written.add(k)
    for k, v in interface.items():
        if k not in written and v:
            lines.append(f"{k} = {v}")

    for peer in peers:
        lines.append("")
        if peer.get("name"):
            lines.append(f"# Name: {peer['name']}")
        lines.append("[Peer]")
        peer_order = ["PublicKey", "PresharedKey", "AllowedIPs", "Endpoint", "PersistentKeepalive"]
        written_p: set[str] = set()
        for k in peer_order:
            if peer.get(k):
                lines.append(f"{k} = {peer[k]}")
                written_p.add(k)
        for k, v in peer.items():
            if k not in written_p and k != "name" and v:
                lines.append(f"{k} = {v}")

    return "\n".join(lines) + "\n"


def _write_conf(iface: str, content: str) -> tuple[bool, str]:
    """Write config via temp file + sudo cp."""
    path = WG_DIR / f"{iface}.conf"
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as f:
            f.write(content)
            tmp = f.name
        _, err, rc = _run(["sudo", "cp", tmp, str(path)], timeout=5)
        try:
            os.unlink(tmp)
        except OSError:
            pass
        if rc != 0:
            return False, err or "sudo cp failed"
        _run(["sudo", "chmod", "600", str(path)], timeout=5)
        return True, ""
    except Exception as e:
        return False, str(e)


def _iface_list() -> list[str]:
    if not WG_DIR.is_dir():
        return []
    return sorted(p.stem for p in WG_DIR.glob("*.conf"))


def _mask_privkey(content: str) -> str:
    return re.sub(r"(PrivateKey\s*=\s*)(\S+)", r"\1[hidden]", content)


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class PeerModel(BaseModel):
    name: Optional[str] = ""
    PublicKey: str
    AllowedIPs: str
    Endpoint: Optional[str] = ""
    PersistentKeepalive: Optional[str] = ""
    PresharedKey: Optional[str] = ""

    @field_validator("PublicKey")
    @classmethod
    def valid_pubkey(cls, v: str) -> str:
        if not _KEY_RE.match(v.strip()):
            raise ValueError("Invalid WireGuard public key format")
        return v.strip()

    @field_validator("AllowedIPs")
    @classmethod
    def valid_ips(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("AllowedIPs cannot be empty")
        return v.strip()


class InterfaceCreateModel(BaseModel):
    name: str
    Address: str
    ListenPort: str = "51820"
    PrivateKey: Optional[str] = ""
    DNS: Optional[str] = ""
    enable_nat: bool = True
    nat_interface: str = "eth0"
    auto_up: bool = False

    @field_validator("name")
    @classmethod
    def safe_name(cls, v: str) -> str:
        clean = re.sub(r"[^a-zA-Z0-9_\-]", "", v)
        if not clean:
            raise ValueError("Invalid interface name")
        return clean

    @field_validator("Address")
    @classmethod
    def valid_addr(cls, v: str) -> str:
        if not re.match(r"[\d.:/]+", v.strip()):
            raise ValueError("Invalid address — use CIDR notation, e.g. 10.0.0.1/24")
        return v.strip()


class RawConfigModel(BaseModel):
    content: str

    @field_validator("content")
    @classmethod
    def has_interface(cls, v: str) -> str:
        if "[Interface]" not in v and "[interface]" not in v:
            raise ValueError("Config must contain an [Interface] section")
        return v


class ActionModel(BaseModel):
    action: str

    @field_validator("action")
    @classmethod
    def valid_action(cls, v: str) -> str:
        allowed = {"up", "down", "reload", "restart", "enable", "disable"}
        if v.lower() not in allowed:
            raise ValueError(f"action must be one of: {', '.join(sorted(allowed))}")
        return v.lower()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("")
async def list_interfaces(_: str = Depends(require_super_admin)) -> dict:
    available = _wg_available()
    ifaces = _iface_list()
    live = _wg_status()
    result = []
    for name in ifaces:
        try:
            parsed = _parse_conf(WG_DIR / f"{name}.conf")
            icfg = parsed["interface"]
            peer_count = len(parsed["peers"])
        except Exception:
            icfg, peer_count = {}, 0
        lv = live.get(name, {})
        result.append({
            "name": name,
            "address": icfg.get("Address", ""),
            "listen_port": icfg.get("ListenPort", ""),
            "peer_count": peer_count,
            "running": name in live,
            "has_dns": bool(icfg.get("DNS")),
            "live_public_key": lv.get("public_key", ""),
        })
    return {
        "available": available,
        "wg_dir_exists": WG_DIR.is_dir(),
        "interfaces": result,
        "count": len(result),
        "checked_at": datetime.now(UTC).isoformat(),
    }


@router.get("/status")
async def wg_show(_: str = Depends(require_super_admin)) -> dict:
    """Raw `sudo wg show` output."""
    out, err, rc = _run(["sudo", "wg", "show"], timeout=8)
    return {
        "available": _wg_available(),
        "output": out or err,
        "ok": rc == 0,
    }


@router.get("/generate-keys")
async def generate_keys(_: str = Depends(require_super_admin)) -> dict:
    """Generate a WireGuard private/public key pair."""
    if not _wg_available():
        raise HTTPException(503, "wireguard-tools not installed — install it with: apt install wireguard-tools")
    priv_out, _, rc1 = _run(["wg", "genkey"], timeout=5)
    if rc1 != 0:
        raise HTTPException(500, "wg genkey failed")
    priv = priv_out.strip()
    pub_out, _, rc2 = _run(["bash", "-c", f"printf '%s' '{priv}' | wg pubkey"], timeout=5)
    if rc2 != 0:
        raise HTTPException(500, "wg pubkey failed")
    return {"private_key": priv, "public_key": pub_out.strip()}


@router.get("/{iface}")
async def get_interface(iface: str, _: str = Depends(require_super_admin)) -> dict:
    iface = re.sub(r"[^a-zA-Z0-9_\-]", "", iface)
    conf_path = WG_DIR / f"{iface}.conf"
    if not conf_path.exists():
        raise HTTPException(404, f"Interface config not found: {iface}")
    parsed = _parse_conf(conf_path)
    raw = conf_path.read_text(errors="replace")
    live = _wg_status()
    live_peers = live.get(iface, {}).get("live_peers", [])

    # Merge live handshake data into parsed peers
    live_by_key = {p["public_key"]: p for p in live_peers}
    for peer in parsed["peers"]:
        pk = peer.get("PublicKey", "")
        lp = live_by_key.get(pk, {})
        peer["_last_handshake"] = lp.get("last_handshake", 0)
        peer["_rx_bytes"] = lp.get("rx_bytes", 0)
        peer["_tx_bytes"] = lp.get("tx_bytes", 0)
        peer["_endpoint_live"] = lp.get("endpoint", "")

    return {
        "name": iface,
        "interface": parsed["interface"],
        "peers": parsed["peers"],
        "raw_masked": _mask_privkey(raw),
        "running": iface in live,
        "live_public_key": live.get(iface, {}).get("public_key", ""),
        "checked_at": datetime.now(UTC).isoformat(),
    }


@router.get("/{iface}/raw")
async def get_raw(iface: str, _: str = Depends(require_super_admin)) -> dict:
    """Return the full raw config including unmasked private key."""
    iface = re.sub(r"[^a-zA-Z0-9_\-]", "", iface)
    conf_path = WG_DIR / f"{iface}.conf"
    if not conf_path.exists():
        raise HTTPException(404, f"Interface config not found: {iface}")
    return {"iface": iface, "content": conf_path.read_text(errors="replace")}


@router.put("/{iface}/raw")
async def save_raw(iface: str, body: RawConfigModel, _: str = Depends(require_super_admin)) -> dict:
    iface = re.sub(r"[^a-zA-Z0-9_\-]", "", iface)
    if not WG_DIR.is_dir():
        raise HTTPException(503, "/etc/wireguard does not exist")
    ok, err = _write_conf(iface, body.content)
    if not ok:
        raise HTTPException(500, f"Write failed: {err}")
    return {"ok": True, "iface": iface}


@router.post("/{iface}/peers")
async def add_peer(iface: str, peer: PeerModel, _: str = Depends(require_super_admin)) -> dict:
    iface = re.sub(r"[^a-zA-Z0-9_\-]", "", iface)
    conf_path = WG_DIR / f"{iface}.conf"
    if not conf_path.exists():
        raise HTTPException(404, f"Interface {iface} not found")
    parsed = _parse_conf(conf_path)
    for p in parsed["peers"]:
        if p.get("PublicKey") == peer.PublicKey:
            raise HTTPException(409, "A peer with this public key already exists")
    new = {k: v for k, v in peer.model_dump().items() if v}
    parsed["peers"].append(new)
    ok, err = _write_conf(iface, _build_conf(parsed["interface"], parsed["peers"]))
    if not ok:
        raise HTTPException(500, f"Write failed: {err}")
    return {"ok": True, "peer_count": len(parsed["peers"])}


@router.put("/{iface}/peers/{idx}")
async def update_peer(iface: str, idx: int, peer: PeerModel, _: str = Depends(require_super_admin)) -> dict:
    iface = re.sub(r"[^a-zA-Z0-9_\-]", "", iface)
    conf_path = WG_DIR / f"{iface}.conf"
    if not conf_path.exists():
        raise HTTPException(404, f"Interface {iface} not found")
    parsed = _parse_conf(conf_path)
    if idx < 0 or idx >= len(parsed["peers"]):
        raise HTTPException(404, "Peer index out of range")
    parsed["peers"][idx] = {k: v for k, v in peer.model_dump().items() if v}
    ok, err = _write_conf(iface, _build_conf(parsed["interface"], parsed["peers"]))
    if not ok:
        raise HTTPException(500, f"Write failed: {err}")
    return {"ok": True}


@router.delete("/{iface}/peers/{idx}")
async def remove_peer(iface: str, idx: int, _: str = Depends(require_super_admin)) -> dict:
    iface = re.sub(r"[^a-zA-Z0-9_\-]", "", iface)
    conf_path = WG_DIR / f"{iface}.conf"
    if not conf_path.exists():
        raise HTTPException(404, f"Interface {iface} not found")
    parsed = _parse_conf(conf_path)
    if idx < 0 or idx >= len(parsed["peers"]):
        raise HTTPException(404, "Peer index out of range")
    parsed["peers"].pop(idx)
    ok, err = _write_conf(iface, _build_conf(parsed["interface"], parsed["peers"]))
    if not ok:
        raise HTTPException(500, f"Write failed: {err}")
    return {"ok": True}


@router.post("/{iface}/action")
async def interface_action(iface: str, body: ActionModel, _: str = Depends(require_super_admin)) -> dict:
    iface = re.sub(r"[^a-zA-Z0-9_\-]", "", iface)
    if not _wg_available():
        raise HTTPException(503, "wireguard-tools not installed")
    action = body.action

    if action == "up":
        out, err, rc = _run(["sudo", "wg-quick", "up", iface], timeout=15)
    elif action == "down":
        out, err, rc = _run(["sudo", "wg-quick", "down", iface], timeout=15)
    elif action == "reload":
        _run(["sudo", "wg-quick", "down", iface], timeout=15)
        out, err, rc = _run(["sudo", "wg-quick", "up", iface], timeout=15)
    elif action == "restart":
        out, err, rc = _run(["sudo", "systemctl", "restart", f"wg-quick@{iface}"], timeout=20)
    elif action == "enable":
        out, err, rc = _run(["sudo", "systemctl", "enable", "--now", f"wg-quick@{iface}"], timeout=15)
    elif action == "disable":
        out, err, rc = _run(["sudo", "systemctl", "disable", "--now", f"wg-quick@{iface}"], timeout=15)
    else:
        raise HTTPException(400, "Unknown action")

    return {"ok": rc == 0, "output": (out + err).strip(), "action": action}


@router.post("")
async def create_interface(body: InterfaceCreateModel, _: str = Depends(require_super_admin)) -> dict:
    iface = body.name
    if not _wg_available():
        raise HTTPException(503, "wireguard-tools not installed — run: apt install wireguard-tools")
    if not WG_DIR.is_dir():
        raise HTTPException(503, "/etc/wireguard does not exist — run: apt install wireguard")

    conf_path = WG_DIR / f"{iface}.conf"
    if conf_path.exists():
        raise HTTPException(409, f"Interface {iface} already exists")

    # Key generation
    private_key = body.PrivateKey or ""
    if not private_key:
        priv_out, _, rc = _run(["wg", "genkey"], timeout=5)
        if rc != 0:
            raise HTTPException(500, "wg genkey failed")
        private_key = priv_out.strip()

    pub_out, _, rc2 = _run(["bash", "-c", f"printf '%s' '{private_key}' | wg pubkey"], timeout=5)
    if rc2 != 0:
        raise HTTPException(500, "wg pubkey failed")
    public_key = pub_out.strip()

    interface: dict[str, str] = {
        "Address": body.Address,
        "ListenPort": body.ListenPort,
        "PrivateKey": private_key,
    }
    if body.DNS:
        interface["DNS"] = body.DNS
    if body.enable_nat:
        nat = body.nat_interface
        interface["PostUp"] = (
            f"iptables -A FORWARD -i {iface} -j ACCEPT; "
            f"iptables -A FORWARD -o {iface} -j ACCEPT; "
            f"iptables -t nat -A POSTROUTING -o {nat} -j MASQUERADE"
        )
        interface["PostDown"] = (
            f"iptables -D FORWARD -i {iface} -j ACCEPT; "
            f"iptables -D FORWARD -o {iface} -j ACCEPT; "
            f"iptables -t nat -D POSTROUTING -o {nat} -j MASQUERADE"
        )

    ok, err = _write_conf(iface, _build_conf(interface, []))
    if not ok:
        raise HTTPException(500, f"Failed to write config: {err}")

    result: dict = {
        "ok": True,
        "iface": iface,
        "public_key": public_key,
        "address": body.Address,
        "listen_port": body.ListenPort,
    }

    if body.auto_up:
        out, err_up, rc_up = _run(["sudo", "wg-quick", "up", iface], timeout=15)
        result["up_output"] = (out + err_up).strip()
        result["up_ok"] = rc_up == 0

    return result


@router.delete("/{iface}")
async def delete_interface(iface: str, _: str = Depends(require_super_admin)) -> dict:
    iface = re.sub(r"[^a-zA-Z0-9_\-]", "", iface)
    conf_path = WG_DIR / f"{iface}.conf"
    if not conf_path.exists():
        raise HTTPException(404, f"Interface {iface} not found")
    # Bring down gracefully (ignore errors)
    _run(["sudo", "wg-quick", "down", iface], timeout=15)
    _, err, rc = _run(["sudo", "rm", str(conf_path)], timeout=5)
    if rc != 0:
        raise HTTPException(500, f"Failed to delete: {err}")
    return {"ok": True, "iface": iface}
