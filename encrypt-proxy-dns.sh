#!/bin/sh
# 代理核心 DNS 配置工具 v1.1.1 | 运行：sh encrypt-proxy-dns.sh
# 默认自动扫描、检查、备份、写入并重启已运行的对应服务，无需选择。
# 仅预览：sh encrypt-proxy-dns.sh --dry-run | 帮助：--help | 版本：--version
# 单文件分发：内嵌 Python，无需其他源码或 pip 依赖。
if ! command -v python3 >/dev/null 2>&1; then
    echo '需要 Python 3.9+。Alpine: apk add python3；Debian/Ubuntu: apt-get update && apt-get install -y python3' >&2
    exit 1
fi

exec python3 - "$@" <<'ENCRYPT_PROXY_DNS_PYTHON'
"""把 LXC 里代理核心的 DNS 上游换成三家海外加密 DNS。

只处理 sing-box、xray、v2ray、mihomo / clash-meta。
不改 mosdns、smartdns、dnsmasq、systemd-resolved。

三家都用带 IP 证书的地址，连接时不再做明文引导查询：

  Cloudflare  1.1.1.1   DoH
  Google      8.8.8.8   DoT（mixed 默认）
  Quad9       9.9.9.9   DoH

xray / v2ray 没有可用的 DoT，这三家都写成 DoH。
xray 用 https+local，从本机直接连，不把 DNS 再送进路由。

默认自动处理并重启服务；--dry-run 仅预览。需要 Python 3.9+。
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any

VERSION = "1.1.1"


PROVIDERS = (
    {"id": "cloudflare", "ip": "1.1.1.1", "sni": "cloudflare-dns.com"},
    {"id": "google", "ip": "8.8.8.8", "sni": "dns.google"},
    {"id": "quad9", "ip": "9.9.9.9", "sni": "dns.quad9.net"},
)

SINGBOX_TYPES = {
    "udp",
    "tcp",
    "tls",
    "https",
    "quic",
    "h3",
    "dhcp",
    "fakeip",
    "fake-ip",
    "hosts",
    "local",
    "tailscale",
    "resolved",
}
KEEP_SINGBOX_TYPES = {"fakeip", "fake-ip", "hosts", "local", "dhcp", "tailscale", "resolved"}
KEEP_ADDR_HEADS = {"fakeip", "fake-ip", "local", "hosts", "dhcp"}
KEEP_URL_PREFIXES = ("rcode://", "ts://", "tailscale://", "et://", "easytier://")
FINAL_KEEP_TYPES = {"fakeip", "fake-ip", "hosts"}

SERVER_LIST_KEYS = {
    "nameserver",
    "fallback",
    "default-nameserver",
    "proxy-server-nameserver",
    "direct-nameserver",
}
POLICY_KEYS = {"nameserver-policy", "proxy-server-nameserver-policy"}

NON_PUBLIC_NETS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

KNOWN_DIRS = (
    "etc/sing-box",
    "usr/local/etc/sing-box",
    "etc/xray",
    "usr/local/etc/xray",
    "etc/v2ray",
    "usr/local/etc/v2ray",
    "etc/mihomo",
    "etc/clash",
    "etc/clash-meta",
    "opt/sing-box",
    "opt/xray",
    "opt/mihomo",
    "opt/clash-meta",
    "root/.config/sing-box",
    "root/.config/mihomo",
    "root/.config/clash",
)
WALK_ROOTS = ("etc", "usr/local/etc", "opt", "root", "home", "var/lib")
PRUNE_DIRS = {
    "proc",
    "sys",
    "dev",
    "run",
    "tmp",
    "cache",
    "apk",
    "dpkg",
    "docker",
    "containerd",
    "lxc",
    "libvirt",
    "machines",
    "snap",
    "flatpak",
    "overlay2",
    "node_modules",
    ".git",
}
PATH_KEYWORDS = ("sing-box", "singbox", "xray", "v2ray", "mihomo", "clash")
CONFIG_EXTS = {".json", ".jsonc", ".yaml", ".yml"}
MAX_BYTES = 2_000_000
SERVICE_NAMES = {
    "sing-box": ("sing-box",),
    "xray": ("xray",),
    "v2ray": ("v2ray",),
    "mihomo": ("mihomo", "clash-meta", "clash"),
}


class Change:
    def __init__(self, path: str, kind: str, notes: list[str], new_text: str | None):
        self.path = path
        self.kind = kind
        self.notes = notes
        self.new_text = new_text


def protocol_for(index: int, protocol: str) -> str:
    if protocol == "doh":
        return "doh"
    if protocol == "dot":
        return "dot"
    return "dot" if index == 1 else "doh"


def url_endpoint(provider: dict[str, str], kind: str) -> str:
    if kind == "dot":
        return "tls://{ip}:853".format(ip=provider["ip"])
    return "https://{ip}/dns-query".format(ip=provider["ip"])


def mihomo_endpoints(protocol: str) -> list[str]:
    return [url_endpoint(p, protocol_for(i, protocol)) for i, p in enumerate(PROVIDERS)]


def xray_endpoints(local: bool) -> list[str]:
    scheme = "https+local" if local else "https"
    return ["{scheme}://{ip}/dns-query".format(scheme=scheme, ip=p["ip"]) for p in PROVIDERS]


def is_non_public_ip(host: str) -> bool:
    text = host.strip().strip("[]")
    if "%" in text:
        text = text.split("%", 1)[0]
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return any(ip in net for net in NON_PUBLIC_NETS)


def extract_host(url: str) -> str:
    value = url.strip()
    if "#" in value:
        value = value.split("#", 1)[0]
    if "://" in value:
        value = value.split("://", 1)[1]
    value = value.split("/", 1)[0]
    if "@" in value:
        value = value.split("@", 1)[1]
    if value.startswith("["):
        end = value.find("]")
        if end != -1:
            return value[1:end]
    if value.count(":") == 1:
        host, port = value.rsplit(":", 1)
        if port.isdigit():
            return host
    return value


def is_kept_url(url: str) -> bool:
    low = url.strip().lower()
    if low.startswith(KEEP_URL_PREFIXES):
        return True
    host = extract_host(url)
    return bool(host) and is_non_public_ip(host)


def normalize_servers(servers: list[str], canonical: list[str]) -> list[str]:
    kept = [item for item in servers if is_kept_url(item)]
    public = [item for item in servers if not is_kept_url(item)]
    if not public and servers:
        return list(servers)
    return kept + list(canonical)


def strip_jsonc(text: str) -> str:
    out: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == '"':
            out.append(ch)
            i += 1
            while i < n:
                out.append(text[i])
                if text[i] == "\\" and i + 1 < n:
                    out.append(text[i + 1])
                    i += 2
                    continue
                if text[i] == '"':
                    i += 1
                    break
                i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            i += 2
            while i < n and text[i] not in "\n\r":
                i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i = min(n, i + 2)
            continue
        if ch == ",":
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if j < n and text[j] in "}]":
                i += 1
                continue
        out.append(ch)
        i += 1
    return "".join(out)


def loads_jsonc(text: str) -> Any:
    return json.loads(strip_jsonc(text))


def json_has_comments(text: str) -> bool:
    stripped = strip_jsonc(text)
    return stripped != text and ("//" in text or "/*" in text)


def detect_indent(text: str) -> str | int:
    match = re.search(r"\n(\t+)", text)
    if match:
        return "\t"
    match = re.search(r'\n( +)"', text)
    if match:
        return len(match.group(1))
    return 2


def dump_json(data: Any, indent: str | int) -> str:
    return json.dumps(data, ensure_ascii=False, indent=indent) + "\n"


def singbox_keep_server(server: dict[str, Any]) -> bool:
    typ = str(server.get("type") or "").lower()
    if typ in KEEP_SINGBOX_TYPES:
        return True
    address = str(server.get("address") or "")
    head = address.split("://", 1)[0].lower() if address else ""
    if head in KEEP_ADDR_HEADS or address.lower().startswith(KEEP_URL_PREFIXES):
        return True
    host = server.get("server") if typ else ""
    if not host:
        host = extract_host(address) if address else ""
    if isinstance(host, str) and host and is_non_public_ip(host):
        return True
    return False


def singbox_fake_tag(server: dict[str, Any]) -> str | None:
    typ = str(server.get("type") or "").lower()
    address = str(server.get("address") or "").lower()
    head = address.split("://", 1)[0] if address else ""
    if typ in FINAL_KEEP_TYPES or head in FINAL_KEEP_TYPES:
        tag = server.get("tag")
        if isinstance(tag, str) and tag:
            return tag
    return None


def pick_singbox_schema(servers: list[Any], version: tuple[int, int] | None) -> str:
    kinds: set[str] = set()
    for server in servers:
        if not isinstance(server, dict):
            continue
        if "type" in server and "address" not in server:
            kinds.add("new")
        elif "address" in server and "type" not in server:
            kinds.add("legacy")
    if kinds == {"new"}:
        return "new"
    if kinds == {"legacy"}:
        return "legacy"
    if version is not None and version >= (1, 12):
        return "new"
    return "legacy"


def direct_outbound_tag(cfg: dict[str, Any]) -> str | None:
    outbounds = cfg.get("outbounds")
    if not isinstance(outbounds, list):
        return None
    found = None
    for outbound in outbounds:
        if isinstance(outbound, dict) and outbound.get("type") == "direct":
            tag = outbound.get("tag") or "direct"
            if tag == "direct":
                return "direct"
            if found is None:
                found = tag
    return found


def alloc_tag(base: str, used: set[str]) -> str:
    if base not in used:
        used.add(base)
        return base
    number = 2
    while "{0}-{1}".format(base, number) in used:
        number += 1
    tag = "{0}-{1}".format(base, number)
    used.add(tag)
    return tag


def singbox_server(provider: dict[str, str], kind: str, tag: str, schema: str, detour: str | None) -> dict[str, Any]:
    if schema == "new":
        if kind == "dot":
            return {
                "type": "tls",
                "tag": tag,
                "server": provider["ip"],
                "server_port": 853,
                "tls": {"enabled": True, "server_name": provider["sni"]},
            }
        return {
            "type": "https",
            "tag": tag,
            "server": provider["ip"],
            "server_port": 443,
            "path": "/dns-query",
            "tls": {"enabled": True, "server_name": provider["sni"]},
        }
    entry: dict[str, Any] = {"tag": tag, "address": url_endpoint(provider, kind)}
    if detour:
        entry["detour"] = detour
    return entry


def walk_resolvers(obj: Any, old_tags: set[str], new_tag: str, notes: list[str]) -> None:
    if isinstance(obj, dict):
        default = obj.get("default_domain_resolver")
        if isinstance(default, str) and default in old_tags:
            obj["default_domain_resolver"] = new_tag
            notes.append("default_domain_resolver {0} -> {1}".format(default, new_tag))
        elif isinstance(default, dict) and default.get("server") in old_tags:
            default["server"] = new_tag
            notes.append("default_domain_resolver -> " + new_tag)
        resolver = obj.get("domain_resolver")
        if isinstance(resolver, str) and resolver in old_tags:
            obj["domain_resolver"] = new_tag
            notes.append("domain_resolver {0} -> {1}".format(resolver, new_tag))
        elif isinstance(resolver, dict) and resolver.get("server") in old_tags:
            previous = resolver["server"]
            resolver["server"] = new_tag
            notes.append("domain_resolver {0} -> {1}".format(previous, new_tag))
        address_resolver = obj.get("address_resolver")
        if isinstance(address_resolver, str) and address_resolver in old_tags:
            obj["address_resolver"] = new_tag
            notes.append("address_resolver {0} -> {1}".format(address_resolver, new_tag))
        for value in obj.values():
            walk_resolvers(value, old_tags, new_tag, notes)
    elif isinstance(obj, list):
        for value in obj:
            walk_resolvers(value, old_tags, new_tag, notes)


def retarget_dns_rules(rules: Any, old_tags: set[str], new_tag: str, notes: list[str]) -> None:
    if not isinstance(rules, list):
        return
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        if rule.get("server") in old_tags:
            previous = rule["server"]
            rule["server"] = new_tag
            notes.append("dns 规则 {0} -> {1}".format(previous, new_tag))
        if isinstance(rule.get("rules"), list):
            retarget_dns_rules(rule["rules"], old_tags, new_tag, notes)


def rewrite_singbox(
    cfg: dict[str, Any],
    protocol: str,
    version: tuple[int, int] | None,
    add_if_missing: bool,
) -> list[str]:
    notes: list[str] = []
    dns = cfg.get("dns")
    has_dns = isinstance(dns, dict)
    if not has_dns:
        if not add_if_missing:
            return []
        dns = {}
        cfg["dns"] = dns
        notes.append("原配置缺少 dns，已添加加密上游")
    servers = dns.get("servers")
    if not isinstance(servers, list):
        servers = []
    schema = pick_singbox_schema(servers, version)
    kept = [server for server in servers if isinstance(server, dict) and singbox_keep_server(server)]
    removed = [server for server in servers if server not in kept]
    if removed:
        shown = []
        for server in removed:
            if isinstance(server, dict):
                shown.append(str(server.get("tag") or server.get("address") or server.get("server") or server.get("type")))
            else:
                shown.append(str(server))
        notes.append("移除原上游: " + ", ".join(shown[:8]))
    used = {server.get("tag") for server in kept if isinstance(server, dict) and isinstance(server.get("tag"), str)}
    detour = direct_outbound_tag(cfg) if schema == "legacy" else None
    built = []
    tags = []
    for index, provider in enumerate(PROVIDERS):
        tag = alloc_tag("dns-" + provider["id"], used)
        tags.append(tag)
        built.append(singbox_server(provider, protocol_for(index, protocol), tag, schema, detour))
    new_servers = list(kept) + built
    old_tags = set()
    for server in removed:
        if isinstance(server, dict) and isinstance(server.get("tag"), str):
            old_tags.add(server["tag"])
    primary = tags[0]
    dns["servers"] = new_servers
    retarget_dns_rules(dns.get("rules"), old_tags, primary, notes)
    keep_final = {tag for server in kept if (tag := singbox_fake_tag(server))}
    final = dns.get("final")
    if final not in keep_final:
        if final != primary:
            if isinstance(final, str) and final:
                notes.append("final {0} -> {1}".format(final, primary))
            else:
                notes.append("final -> {0}".format(primary))
        dns["final"] = primary
    walk_resolvers(cfg, old_tags, primary, notes)
    retarget_dns_rules(cfg.get("route", {}).get("rules"), old_tags, primary, notes)
    ensure_singbox_resolution(cfg, primary, version, schema, notes)
    if not notes and new_servers == servers and dns.get("final") == final:
        return []
    if schema == "new":
        notes.insert(0, "sing-box DNS 格式: 1.12+")
    else:
        notes.insert(0, "sing-box DNS 格式: legacy address")
    labels = []
    for index, provider in enumerate(PROVIDERS):
        labels.append("{0} {1}".format(tags[index], url_endpoint(provider, protocol_for(index, protocol))))
    notes.insert(1, "上游: " + " | ".join(labels))
    return notes


def ensure_singbox_resolution(
    cfg: dict[str, Any], primary: str, version: tuple[int, int] | None,
    schema: str, notes: list[str],
) -> None:
    # DNS configuration alone does not enable legacy direct dialer resolution.
    # Include relay server names, Reality handshakes and the YYDS NTP server.
    modern = version >= (1, 12) if version is not None else schema == "new"
    if modern:
        route = cfg.setdefault("route", {})
        if not route.get("default_domain_resolver"):
            route["default_domain_resolver"] = primary
            notes.append("route.default_domain_resolver -> " + primary)
        return

    dialers = [item for item in cfg.get("outbounds", [])
               if isinstance(item, dict) and (item.get("type") == "direct" or "server" in item)]
    for inbound in cfg.get("inbounds", []):
        if not isinstance(inbound, dict):
            continue
        handshake = inbound.get("tls", {}).get("reality", {}).get("handshake")
        if isinstance(handshake, dict):
            dialers.append(handshake)
    if isinstance(cfg.get("ntp"), dict) and cfg["ntp"].get("enabled"):
        dialers.append(cfg["ntp"])
    for dialer in dialers:
        if not dialer.get("detour") and dialer.get("domain_strategy", "") in {"", "as_is"}:
            dialer["domain_strategy"] = "prefer_ipv4"
            notes.append("{0}: domain_strategy -> prefer_ipv4（使用内置 DNS）".format(
                dialer.get("tag") or dialer.get("server") or "direct"))


def xray_keep(entry: Any) -> bool:
    if isinstance(entry, str):
        if entry.lower() in {"fakedns", "fakedns+local"}:
            return True
        return is_kept_url(entry)
    if isinstance(entry, dict):
        address = str(entry.get("address") or "")
        if address.lower() in {"fakedns", "fakedns+local"}:
            return True
        return is_kept_url(address)
    return False


def rewrite_xray(cfg: dict[str, Any], local: bool, add_if_missing: bool) -> list[str]:
    notes: list[str] = []
    dns = cfg.get("dns")
    has_dns = isinstance(dns, dict)
    if not has_dns:
        if not add_if_missing:
            return []
        dns = {}
        cfg["dns"] = dns
        notes.append("原配置缺少 dns，已添加 DoH")
    servers = dns.get("servers")
    if not isinstance(servers, list):
        servers = []
    kept = [entry for entry in servers if xray_keep(entry)]
    removed = [entry for entry in servers if entry not in kept]
    endpoints = xray_endpoints(local)
    new_servers = list(kept) + endpoints
    if new_servers == servers and has_dns:
        return []
    if removed:
        shown = []
        for entry in removed:
            if isinstance(entry, str):
                shown.append(entry)
            elif isinstance(entry, dict):
                shown.append(str(entry.get("address") or entry))
        notes.append("移除原上游: " + ", ".join(shown[:8]))
    dns["servers"] = new_servers
    mode = "https+local DoH" if local else "DoH"
    notes.insert(0, "xray 家族不支持 DoT，三家都用 {0}".format(mode))
    notes.insert(1, "上游: " + " | ".join(endpoints))
    return notes


def core_family(cfg: dict[str, Any]) -> str | None:
    blobs: list[dict[str, Any]] = []
    for key in ("inbounds", "outbounds"):
        value = cfg.get(key)
        if isinstance(value, list):
            blobs.extend(item for item in value if isinstance(item, dict))
    has_type = any("type" in item and "protocol" not in item for item in blobs)
    has_protocol = any("protocol" in item for item in blobs)
    if has_protocol and not has_type:
        return "xray"
    if has_type and not has_protocol:
        return "sing-box"
    if has_protocol and has_type:
        protocols = sum(1 for item in blobs if "protocol" in item)
        types = sum(1 for item in blobs if "type" in item and "protocol" not in item)
        return "xray" if protocols >= types else "sing-box"
    dns = cfg.get("dns")
    if isinstance(dns, dict) and isinstance(dns.get("servers"), list):
        for server in dns["servers"]:
            if isinstance(server, str):
                return "xray"
            if isinstance(server, dict) and any(
                key in server for key in ("domains", "skipFallback", "expectIPs", "expectedIPs", "clientIP")
            ):
                return "xray"
            if isinstance(server, dict) and (
                "tag" in server or server.get("type") in SINGBOX_TYPES or "address" in server
            ):
                return "sing-box"
    if "route" in cfg and ("inbounds" in cfg or "outbounds" in cfg):
        return "sing-box"
    if "routing" in cfg and ("inbounds" in cfg or "outbounds" in cfg):
        return "xray"
    proxies = cfg.get("proxies")
    if isinstance(proxies, list) or isinstance(cfg.get("proxy-groups"), list):
        return "mihomo"
    return None


def looks_like_mihomo_text(text: str) -> bool:
    if re.search(r"(?m)^(proxies|proxy-groups|proxy-providers):\s*(?:$|#)", text):
        return True
    if re.search(r"(?m)^dns:\s*(?:$|#)", text) and re.search(
        r"(?m)^(mixed-port|redir-port|tproxy-port|socks-port|port|listeners|mode):\s*",
        text,
    ):
        return True
    return False


def classify_text(path: str, text: str, hint: str | None) -> str | None:
    stripped = text.lstrip()
    ext = os.path.splitext(path)[1].lower()
    if hint in {"mihomo", "clash", "clash-meta"} or ext in {".yaml", ".yml"} or stripped.startswith(("proxies:", "dns:")):
        if looks_like_mihomo_text(text):
            return "mihomo"
    if not (ext in {".json", ".jsonc", ""} or stripped.startswith("{")):
        if hint in {"sing-box", "xray", "v2ray"} and stripped.startswith("{"):
            pass
        elif not stripped.startswith("{"):
            return None
    if not stripped.startswith("{"):
        return None
    try:
        cfg = loads_jsonc(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(cfg, dict):
        return None
    family = core_family(cfg)
    if family == "mihomo":
        return "mihomo"
    if family == "sing-box" or (family is None and hint == "sing-box" and ("dns" in cfg or "outbounds" in cfg)):
        return "sing-box"
    if family == "xray" or (family is None and hint in {"xray", "v2ray"} and ("dns" in cfg or "outbounds" in cfg)):
        if hint == "v2ray" or "v2ray" in path.replace("\\", "/").lower():
            return "v2ray"
        return "xray"
    return None


def split_yaml_comment(value: str) -> tuple[str, str]:
    in_single = False
    in_double = False
    escaped = False
    for index, char in enumerate(value):
        if in_double and char == "\\" and not escaped:
            escaped = True
            continue
        if char == "'" and not in_double:
            in_single = not in_single
        elif char == '"' and not in_single:
            in_double = not in_double
        elif char == "#" and not in_single and not in_double and (index == 0 or value[index - 1].isspace()):
            return value[:index].rstrip(), value[index:]
        escaped = False
    return value.strip(), ""


def unquote_yaml(value: str) -> str:
    text = value.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "'\"":
        return text[1:-1]
    return text


def split_yaml_key(line: str) -> tuple[int, str, str] | None:
    raw = line.rstrip("\r")
    if not raw.strip() or raw.lstrip().startswith("#"):
        return None
    indent = len(raw) - len(raw.lstrip(" "))
    body = raw.lstrip(" ")
    if body.startswith("- ") or body == "-":
        return None
    if body[0] in "'\"":
        quote = body[0]
        end = body.find(quote, 1)
        if end < 0:
            return None
        rest = body[end + 1 :].lstrip()
        if not rest.startswith(":"):
            return None
        value, _comment = split_yaml_comment(rest[1:].strip())
        return indent, body[1:end], value.strip()
    match = re.match(r"([^:#][^:]*?):\s*(.*)$", body)
    if not match:
        return None
    value, _comment = split_yaml_comment(match.group(2))
    return indent, match.group(1).strip(), value.strip()


def content_indent(line: str) -> int | None:
    if not line.strip() or line.lstrip().startswith("#"):
        return None
    return len(line) - len(line.lstrip(" "))


def parse_flow_seq(value: str) -> list[str] | None:
    text = value.strip()
    if not (text.startswith("[") and text.endswith("]")):
        return None
    inner = text[1:-1]
    items: list[str] = []
    buf: list[str] = []
    quote: str | None = None
    for char in inner:
        if quote:
            buf.append(char)
            if char == quote:
                quote = None
            continue
        if char in "'\"":
            quote = char
            buf.append(char)
            continue
        if char == ",":
            items.append(unquote_yaml("".join(buf)))
            buf = []
            continue
        buf.append(char)
    tail = unquote_yaml("".join(buf))
    if tail:
        items.append(tail)
    return items


def list_items(lines: list[str], inline: str) -> list[str] | None:
    flow = parse_flow_seq(inline) if inline else None
    if flow is not None:
        return flow
    items: list[str] = []
    saw_item = False
    for line in lines[1:]:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = re.match(r"^\s*-\s*(.*?)\s*$", line)
        if not match:
            if line.rstrip().endswith(":") or content_indent(line) is not None:
                return None
            continue
        value, _comment = split_yaml_comment(match.group(1))
        if value.startswith(("|", ">")):
            return None
        saw_item = True
        items.append(unquote_yaml(value))
    if saw_item:
        return items
    if inline:
        return [unquote_yaml(inline)]
    return []


def render_server_block(key_indent: int, key: str, items: list[str], unit: int) -> list[str]:
    pad = " " * key_indent
    lines = ["{0}{1}:".format(pad, key)]
    item_pad = " " * (key_indent + unit)
    for item in items:
        lines.append("{0}- {1}".format(item_pad, item))
    return lines


def block_span(lines: list[str], start: int, end: int, key_indent: int) -> int:
    j = start + 1
    while j < end:
        indent = content_indent(lines[j])
        if indent is None:
            k = j + 1
            while k < end and content_indent(lines[k]) is None:
                k += 1
            if k >= end or content_indent(lines[k]) <= key_indent:  # type: ignore[operator]
                break
            j = k
            continue
        if indent <= key_indent:
            break
        j += 1
    return j


def yaml_key_prefix(line: str) -> str:
    raw = line.rstrip("\r\n")
    body_index = len(raw) - len(raw.lstrip(" "))
    body = raw[body_index:]
    if body[:1] in "'\"":
        quote = body[0]
        end = body.find(quote, 1)
        if end >= 0:
            colon = body.find(":", end + 1)
            if colon >= 0:
                return raw[: body_index + colon + 1]
    colon = body.find(":")
    if colon >= 0:
        return raw[: body_index + colon + 1]
    return raw


def rewrite_policy_span(span: list[str], canonical: list[str], unit: int) -> tuple[list[str], list[str]] | None:
    if not span:
        return None
    key_line = span[0]
    parsed = split_yaml_key(key_line)
    if parsed is None:
        return None
    key_indent, key, _inline = parsed
    notes: list[str] = []
    body = span[1:]
    entry_indent = None
    for line in body:
        indent = content_indent(line)
        if indent is not None and indent > key_indent:
            entry_indent = indent
            break
    if entry_indent is None:
        return [key_line], notes
    out = [key_line]
    index = 0
    changed = False
    while index < len(body):
        indent = content_indent(body[index])
        if indent is None:
            out.append(body[index])
            index += 1
            continue
        if indent != entry_indent or split_yaml_key(body[index]) is None:
            out.append(body[index])
            index += 1
            continue
        entry_end = 1
        while index + entry_end < len(body):
            nxt = content_indent(body[index + entry_end])
            if nxt is None:
                look = index + entry_end + 1
                while look < len(body) and content_indent(body[look]) is None:
                    look += 1
                if look >= len(body) or content_indent(body[look]) <= entry_indent:  # type: ignore[operator]
                    break
                entry_end = look - index
                continue
            if nxt <= entry_indent:
                break
            entry_end += 1
        entry = body[index : index + entry_end]
        entry_key = split_yaml_key(entry[0])
        if entry_key is None:
            out.extend(entry)
            index += entry_end
            continue
        _indent, entry_name, _inline = entry_key
        items = list_items(entry, _inline)
        if items is None:
            raise ValueError("nameserver-policy 里有读不懂的多行值: {0}".format(entry_name))
        desired = normalize_servers(items, canonical)
        if desired == items:
            out.extend(entry)
        else:
            changed = True
            notes.append("策略 {0} 改为加密上游".format(entry_name))
            item_pad = " " * (entry_indent + unit)
            rebuilt = [yaml_key_prefix(entry[0])]
            for item in desired:
                rebuilt.append("{0}- {1}".format(item_pad, item))
            out.extend(rebuilt)
        index += entry_end
    if not changed:
        return span, []
    return out, notes


def ensure_server_key(lines: list[str], dns_end: int, child_indent: int, key: str, items: list[str], unit: int) -> tuple[int, list[str]]:
    block = render_server_block(child_indent, key, items, unit)
    lines[dns_end:dns_end] = block
    return dns_end + len(block), ["补上 {0}".format(key)]


def rewrite_mihomo_yaml(text: str, canonical: list[str]) -> tuple[str, list[str]]:
    if re.search(r"(?m)^dns:\s*\{", text):
        raise ValueError("dns 写成了单行 {}，请改成块状后再跑")
    newline_at_end = text.endswith("\n")
    lines = text.splitlines()
    dns_start = None
    for index, line in enumerate(lines):
        if re.match(r"^dns:\s*(#.*)?$", line):
            dns_start = index
            break
    notes: list[str] = []
    if dns_start is None:
        if not looks_like_mihomo_text(text) and not re.search(r"(?m)^(proxies|proxy-groups|mixed-port|listeners):\s*", text):
            return text, []
        block = ["dns:", "  enable: true"]
        block.extend(render_server_block(2, "nameserver", canonical, 2))
        block.extend(render_server_block(2, "default-nameserver", canonical, 2))
        insert_at = len(lines)
        for index, line in enumerate(lines):
            if re.match(r"^(proxies|proxy-groups|proxy-providers|rules|listeners):\s*", line):
                insert_at = index
                break
        addition = block if insert_at == len(lines) or not lines else block + [""]
        # Keep a blank line before the following section when inserting in the middle.
        if insert_at < len(lines):
            addition = block + [""]
        else:
            if lines and lines[-1].strip():
                addition = [""] + block
            else:
                addition = block
        lines[insert_at:insert_at] = addition
        notes.append("原配置缺少 dns，已添加三家加密上游并 enable: true")
        rendered = "\n".join(lines)
        if newline_at_end or True:
            rendered += "\n"
        return rendered, notes

    dns_end = len(lines)
    for index in range(dns_start + 1, len(lines)):
        if lines[index].strip() and content_indent(lines[index]) == 0 and not lines[index].lstrip().startswith("#"):
            dns_end = index
            break
    child_indent = None
    for line in lines[dns_start + 1 : dns_end]:
        indent = content_indent(line)
        if indent is not None:
            child_indent = indent
            break
    unit = 2 if child_indent is None else max(2, child_indent)
    if child_indent is None:
        child_indent = 2
        lines.insert(dns_start + 1, "  enable: true")
        dns_end += 1
        notes.append("dns.enable -> true")

    present: set[str] = set()
    index = dns_start + 1
    while index < dns_end:
        if content_indent(lines[index]) != child_indent:
            index += 1
            continue
        parsed = split_yaml_key(lines[index])
        if parsed is None:
            index += 1
            continue
        _indent, key, inline = parsed
        span_end = block_span(lines, index, dns_end, child_indent)
        span = lines[index:span_end]
        present.add(key)
        replacement = None
        extra: list[str] = []
        if key == "enable":
            value, comment = split_yaml_comment(inline)
            if value.lower() not in {"true", "yes", "on"}:
                pad = " " * child_indent
                suffix = (" " + comment) if comment else ""
                replacement = ["{0}enable: true{1}".format(pad, suffix)]
                extra = ["dns.enable -> true"]
        elif key in SERVER_LIST_KEYS:
            items = list_items(span, inline)
            if items is None:
                raise ValueError("{0} 的写法不是简单列表，未改这个文件".format(key))
            desired = normalize_servers(items, canonical)
            if desired != items:
                replacement = render_server_block(child_indent, key, desired, unit)
                extra = ["{0} 改为加密上游".format(key)]
        elif key in POLICY_KEYS:
            rewritten = rewrite_policy_span(span, canonical, unit)
            if rewritten is not None:
                new_span, policy_notes = rewritten
                if new_span != span:
                    replacement = new_span
                    extra = policy_notes
        if replacement is not None:
            lines[index:span_end] = replacement
            delta = len(replacement) - (span_end - index)
            dns_end += delta
            index += len(replacement)
            notes.extend(extra)
        else:
            index = span_end

    if "enable" not in present:
        lines.insert(dns_start + 1, "{0}enable: true".format(" " * child_indent))
        dns_end += 1
        notes.append("dns.enable -> true")
    if "nameserver" not in present:
        dns_end, added = ensure_server_key(lines, dns_end, child_indent, "nameserver", canonical, unit)
        notes.extend(added)
    if "default-nameserver" not in present:
        dns_end, added = ensure_server_key(lines, dns_end, child_indent, "default-nameserver", canonical, unit)
        notes.extend(added)
    if notes:
        notes.insert(0, "上游: " + " | ".join(canonical))
    rendered = "\n".join(lines)
    if newline_at_end or not rendered.endswith("\n"):
        if not rendered.endswith("\n"):
            rendered += "\n"
    return rendered, notes


def rewrite_mihomo_json(cfg: dict[str, Any], canonical: list[str]) -> list[str]:
    notes: list[str] = []
    dns = cfg.get("dns")
    if not isinstance(dns, dict):
        dns = {}
        cfg["dns"] = dns
        notes.append("原配置缺少 dns，已添加")
    if dns.get("enable") is not True:
        dns["enable"] = True
        notes.append("dns.enable -> true")

    def assign(key: str, create: bool) -> None:
        if key not in dns and not create:
            return
        current = dns.get(key)
        if isinstance(current, str):
            items = [current]
        elif isinstance(current, list):
            items = [str(item) for item in current]
        elif current is None:
            items = []
        else:
            return
        desired = normalize_servers(items, canonical) if items or create else list(canonical)
        if key not in dns or desired != items:
            dns[key] = desired
            notes.append("{0} 改为加密上游".format(key))

    assign("nameserver", True)
    assign("default-nameserver", True)
    for key in ("fallback", "proxy-server-nameserver", "direct-nameserver"):
        assign(key, False)
    for key in POLICY_KEYS:
        policy = dns.get(key)
        if not isinstance(policy, dict):
            continue
        for name, value in list(policy.items()):
            if isinstance(value, str):
                items = [value]
            elif isinstance(value, list):
                items = [str(item) for item in value]
            else:
                continue
            desired = normalize_servers(items, canonical)
            if desired != items:
                policy[name] = desired
                notes.append("策略 {0} 改为加密上游".format(name))
    if notes:
        notes.insert(0, "上游: " + " | ".join(canonical))
    return notes


def has_outbounds(cfg: dict[str, Any]) -> bool:
    return isinstance(cfg.get("outbounds"), list)


def has_dns(cfg: dict[str, Any]) -> bool:
    return isinstance(cfg.get("dns"), dict)


def choose_dns_owner(items: list[tuple[str, dict[str, Any]]]) -> str | None:
    if any(has_dns(cfg) for _path, cfg in items):
        return None
    outbound_files = sorted(path for path, cfg in items if has_outbounds(cfg))
    if not outbound_files:
        return None
    return outbound_files[0]


def hint_from_name(name: str) -> str | None:
    lowered = os.path.basename(name).lower()
    if "sing-box" in lowered or lowered == "singbox":
        return "sing-box"
    if lowered == "v2ray" or lowered.startswith("v2ray"):
        return "v2ray"
    if "xray" in lowered:
        return "xray"
    if "mihomo" in lowered or "clash-meta" in lowered or "clashmeta" in lowered or "clash" in lowered:
        return "mihomo"
    return None


def configs_from_args(args: list[str], hint: str) -> list[str]:
    found: list[str] = []
    index = 0
    file_flags = {"-c", "-conf", "-config", "--config", "-f", "--config-file"}
    while index < len(args):
        arg = args[index]
        nxt = args[index + 1] if index + 1 < len(args) else None
        if arg in file_flags and nxt and not nxt.startswith("-"):
            found.append(nxt)
            index += 2
            continue
        if arg.startswith("--config=") or arg.startswith("-config="):
            found.append(arg.split("=", 1)[1])
        if hint in {"xray", "v2ray"} and arg in {"-confdir", "--confdir"} and nxt and not nxt.startswith("-"):
            found.append(nxt)
            index += 2
            continue
        if hint == "mihomo" and arg in {"-d", "--directory"} and nxt and not nxt.startswith("-"):
            found.append(os.path.join(nxt, "config.yaml"))
            index += 2
            continue
        index += 1
    return found


def discover_proc() -> list[tuple[str, str | None]]:
    found: list[tuple[str, str | None]] = []
    if not os.path.isdir("/proc"):
        return found
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        cmdline = os.path.join("/proc", pid, "cmdline")
        try:
            with open(cmdline, "rb") as handle:
                raw = handle.read()
        except OSError:
            continue
        args = [part.decode("utf-8", "surrogateescape") for part in raw.split(b"\0") if part]
        if not args:
            continue
        hint = hint_from_name(args[0])
        if hint is None:
            comm_path = os.path.join("/proc", pid, "comm")
            try:
                with open(comm_path, "r", encoding="utf-8", errors="replace") as handle:
                    comm = handle.read().strip()
            except OSError:
                comm = ""
            hint = hint_from_name(comm)
        if hint is None:
            continue
        for path in configs_from_args(args, hint):
            found.append((path, hint))
    return found


def discover_units(root: str) -> list[tuple[str, str | None]]:
    found: list[tuple[str, str | None]] = []
    rels = (
        "etc/systemd/system",
        "lib/systemd/system",
        "usr/lib/systemd/system",
        "etc/init.d",
        "etc/conf.d",
    )
    pattern = re.compile(
        r"(?:--config|-config|--config-file|-confdir|--confdir|-conf|-config-file|-c|-f|-d|--directory)"
        r"(?:=|\s+)([^\s'\";]+)"
    )
    for rel in rels:
        base = os.path.join(root, rel)
        if not os.path.isdir(base):
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [name for name in dirnames if name not in PRUNE_DIRS and not name.startswith(".")]
            for name in filenames:
                path = os.path.join(dirpath, name)
                try:
                    if os.path.getsize(path) > 1_000_000:
                        continue
                    with open(path, "r", encoding="utf-8", errors="replace") as handle:
                        text = handle.read()
                except OSError:
                    continue
                hint = hint_from_name(text) or hint_from_name(name)
                for match in pattern.finditer(text):
                    target = match.group(1)
                    flag = match.group(0)
                    if hint == "mihomo" and re.search(r"(?:^|\s)(?:-d|--directory)(?:=|\s)", flag):
                        target = os.path.join(target, "config.yaml")
                    found.append((target, hint))
    return found


def expand_candidate(path: str) -> list[str]:
    if os.path.isfile(path):
        return [path]
    if not os.path.isdir(path):
        return []
    found: list[str] = []
    for dirpath, dirnames, filenames in os.walk(path):
        dirnames[:] = [name for name in dirnames if name not in PRUNE_DIRS and not name.startswith(".")]
        depth = dirpath[len(path) :].count(os.sep)
        if depth > 2:
            dirnames[:] = []
            continue
        for name in filenames:
            if os.path.splitext(name)[1].lower() in CONFIG_EXTS:
                found.append(os.path.join(dirpath, name))
    return found


def discover(root: str, only_paths: list[str] | None) -> list[tuple[str, str | None]]:
    raw: list[tuple[str, str | None]] = []
    if only_paths:
        for path in only_paths:
            if not os.path.isabs(path):
                path = os.path.join(root, path)
            raw.append((path, hint_from_name(path)))
    else:
        if os.path.abspath(root) == "/":
            raw.extend(discover_proc())
        for path, hint in discover_units(root):
            if os.path.abspath(root) != "/" and os.path.isabs(path):
                path = os.path.join(root, path.lstrip(os.sep))
            raw.append((path, hint))
        for rel in KNOWN_DIRS:
            raw.append((os.path.join(root, rel), None))
        for rel in WALK_ROOTS:
            base = os.path.join(root, rel)
            if not os.path.isdir(base):
                continue
            for dirpath, dirnames, filenames in os.walk(base):
                dirnames[:] = [name for name in dirnames if name not in PRUNE_DIRS and not name.startswith(".")]
                lowered = dirpath.lower()
                if not any(word in lowered for word in PATH_KEYWORDS):
                    continue
                for name in filenames:
                    if ".bak-encrypt-dns-" in name or name.endswith(".bak"):
                        continue
                    if os.path.splitext(name)[1].lower() not in CONFIG_EXTS:
                        continue
                    raw.append((os.path.join(dirpath, name), hint_from_name(dirpath) or hint_from_name(name)))
    selected: list[tuple[str, str | None]] = []
    seen: set[str] = set()
    for path, hint in raw:
        for item in expand_candidate(path):
            if ".bak-encrypt-dns-" in os.path.basename(item) or os.path.basename(item).endswith(".bak"):
                continue
            try:
                if not os.path.isfile(item) or os.path.getsize(item) > MAX_BYTES or os.path.getsize(item) == 0:
                    continue
                real = os.path.realpath(item)
            except OSError:
                continue
            if real in seen:
                continue
            seen.add(real)
            selected.append((item, hint or hint_from_name(item)))
    return selected


def read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def parse_version(text: str) -> tuple[int, int] | None:
    match = re.search(r"(\d+)\.(\d+)", text)
    if not match:
        return None
    return int(match.group(1)), int(match.group(2))


def find_bin(names: tuple[str, ...] | list[str], root: str) -> str | None:
    path_env = os.environ.get("PATH", "") if os.path.abspath(root) == "/" else ""
    for directory in path_env.split(os.pathsep):
        if not directory:
            continue
        for name in names:
            candidate = os.path.join(directory, name)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
    for name in names:
        for rel in ("usr/bin/" + name, "usr/local/bin/" + name, "bin/" + name, "opt/" + name + "/" + name):
            candidate = os.path.join(root, rel)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
    return None


def singbox_version(root: str) -> tuple[int, int] | None:
    binary = find_bin(("sing-box",), root)
    if not binary:
        return None
    try:
        result = subprocess.run(
            [binary, "version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return parse_version(result.stdout + "\n" + result.stderr)


def check_config(kind: str, path: str) -> tuple[bool | None, str]:
    checks = {
        "sing-box": (("sing-box",), ["check", "-c", path]),
        "xray": (("xray",), ["run", "-test", "-config", path]),
        "v2ray": (("v2ray",), ["test", "-config", path]),
        "mihomo": (("mihomo", "clash-meta", "clash"), ["-t", "-f", path]),
    }
    names, args = checks[kind]
    binary = find_bin(names, "/")
    if not binary:
        return None, ""
    try:
        result = subprocess.run(
            [binary, *args],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
            cwd=os.path.dirname(path) or ".",
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    output = (result.stderr or result.stdout or "").strip()
    return result.returncode == 0, output


def service_active(name: str) -> bool:
    if os.path.isdir("/run/systemd/system") and shutil.which("systemctl"):
        result = subprocess.run(["systemctl", "is-active", "--quiet", name], check=False, timeout=10)
        return result.returncode == 0
    if shutil.which("rc-service"):
        result = subprocess.run(
            ["rc-service", name, "status"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
        return result.returncode == 0
    return False


def restart_services(kinds: set[str]) -> tuple[list[str], list[str]]:
    restarted: list[str] = []
    failed: list[str] = []
    use_systemd = os.path.isdir("/run/systemd/system") and shutil.which("systemctl")
    use_openrc = shutil.which("rc-service")
    for kind in sorted(kinds):
        for name in SERVICE_NAMES.get(kind, ()):
            if name in restarted:
                continue
            print("  [状态检查] {0}（最长等待 10 秒）".format(name), flush=True)
            try:
                active = service_active(name)
            except (OSError, subprocess.TimeoutExpired) as exc:
                failed.append("{0}: 服务状态检查失败：{1}".format(name, exc))
                continue
            if not active:
                continue
            command = ["systemctl", "restart", name] if use_systemd else ["rc-service", name, "restart"]
            if not use_systemd and not use_openrc:
                continue
            print("  [正在重启] {0}（最长等待 60 秒）".format(name), flush=True)
            try:
                result = subprocess.run(command, check=False, capture_output=True, text=True, timeout=60)
            except (OSError, subprocess.TimeoutExpired) as exc:
                failed.append("{0}: {1}".format(name, exc))
                continue
            if result.returncode == 0:
                restarted.append(name)
            else:
                failed.append("{0}: {1}".format(name, (result.stderr or result.stdout).strip() or "重启返回非零状态"))
    return restarted, failed


def transform_loaded(
    kind: str,
    text: str,
    cfg: dict[str, Any] | None,
    protocol: str,
    version: tuple[int, int] | None,
    add_if_missing: bool,
) -> tuple[str | None, list[str]]:
    if kind == "mihomo" and cfg is None:
        new_text, notes = rewrite_mihomo_yaml(text, mihomo_endpoints(protocol))
        if new_text == text or not notes:
            return None, []
        return new_text, notes
    if cfg is None:
        return None, []
    updated = json.loads(json.dumps(cfg))
    if kind == "sing-box":
        notes = rewrite_singbox(updated, protocol, version, add_if_missing)
    elif kind in {"xray", "v2ray"}:
        notes = rewrite_xray(updated, local=(kind == "xray"), add_if_missing=add_if_missing)
    elif kind == "mihomo":
        notes = rewrite_mihomo_json(updated, mihomo_endpoints(protocol))
    else:
        return None, []
    if not notes or updated == cfg:
        return None, []
    if json_has_comments(text):
        notes.append("原文件包含注释；写入后不保留注释，原始内容保存在备份中")
    return dump_json(updated, detect_indent(text)), notes


def load_candidate(path: str, hint: str | None) -> tuple[str, str, dict[str, Any] | None] | None:
    try:
        text = read_text(path)
    except (OSError, UnicodeError):
        return None
    kind = classify_text(path, text, hint)
    if kind is None:
        return None
    cfg = None
    if kind != "mihomo" or text.lstrip().startswith("{"):
        if text.lstrip().startswith("{"):
            try:
                loaded = loads_jsonc(text)
            except json.JSONDecodeError:
                if kind != "mihomo":
                    return None
                loaded = None
            if isinstance(loaded, dict):
                cfg = loaded
                if kind == "mihomo" and not text.lstrip().startswith("{"):
                    cfg = None
            elif kind != "mihomo":
                return None
    if kind == "mihomo" and not text.lstrip().startswith("{"):
        cfg = None
    return kind, text, cfg


def plan(root: str, protocol: str, only_paths: list[str] | None, version: tuple[int, int] | None) -> tuple[list[Change], list[str]]:
    errors: list[str] = []
    loaded: list[tuple[str, str, str, dict[str, Any] | None]] = []
    skipped: list[Change] = []
    for path, hint in discover(root, only_paths):
        try:
            item = load_candidate(path, hint)
        except ValueError as exc:
            errors.append("{0}: {1}".format(path, exc))
            continue
        if item is None:
            continue
        kind, text, cfg = item
        if kind == "sing-box" and isinstance(cfg, dict) and "_oboard" in cfg:
            skipped.append(Change(path, kind, [
                "含 _oboard 管理字段，不是可直接交给 sing-box 校验的配置；请通过对应管理程序调整 DNS。"
            ], None))
            continue
        loaded.append((path, kind, text, cfg))

    owners: dict[tuple[str, str], str | None] = {}
    groups: dict[tuple[str, str], list[tuple[str, dict[str, Any]]]] = {}
    for path, kind, _text, cfg in loaded:
        if kind in {"sing-box", "xray", "v2ray"} and isinstance(cfg, dict):
            groups.setdefault((kind, os.path.dirname(os.path.realpath(path))), []).append((path, cfg))
    for key, items in groups.items():
        owners[key] = choose_dns_owner(items)

    changes: list[Change] = list(skipped)
    for path, kind, text, cfg in loaded:
        add_if_missing = False
        if kind in {"sing-box", "xray", "v2ray"} and isinstance(cfg, dict):
            key = (kind, os.path.dirname(os.path.realpath(path)))
            owner = owners.get(key)
            # Complete configs in one directory are independent, not fragments.
            add_if_missing = owner == path or (has_outbounds(cfg) and isinstance(cfg.get("inbounds"), list))
            if has_dns(cfg):
                add_if_missing = True
        try:
            new_text, notes = transform_loaded(kind, text, cfg, protocol, version, add_if_missing)
        except ValueError as exc:
            errors.append("{0}: {1}".format(path, exc))
            continue
        changes.append(Change(path, kind, notes, new_text))
    return changes, errors


def write_text(path: str, data: str) -> None:
    directory = os.path.dirname(path) or "."
    stat = os.stat(path)
    fd, tmp = tempfile.mkstemp(prefix=".encrypt-dns-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(data)
        os.chmod(tmp, stat.st_mode & 0o777)
        try:
            os.chown(tmp, stat.st_uid, stat.st_gid)
        except OSError:
            pass
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def backup_path(path: str) -> str:
    stamp = subprocess.check_output(["date", "-u", "+%Y%m%dT%H%M%SZ"], text=True).strip()
    return "{0}.bak-encrypt-dns-{1}".format(path, stamp)


def apply_change(change: Change, no_check: bool, root: str) -> tuple[bool, str]:
    if change.new_text is None:
        return True, ""
    if not no_check and os.path.abspath(root) == "/":
        directory = os.path.dirname(change.path) or "."
        fd, tmp = tempfile.mkstemp(prefix=".encrypt-dns-check-", suffix=os.path.splitext(change.path)[1], dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(change.new_text)
            ok, output = check_config(change.kind, tmp)
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        if ok is False:
            return False, output
        if ok is None:
            print("  [提示] 未找到 {0} 核心，跳过核心校验；仅完成配置转换检查。".format(change.kind))
    dest = backup_path(change.path)
    shutil.copy2(change.path, dest)
    write_text(change.path, change.new_text)
    return True, dest


def print_report(changes: list[Change], errors: list[str], apply: bool) -> None:
    pending = [item for item in changes if item.new_text is not None]
    skipped_count = sum(item.new_text is None and bool(item.notes) for item in changes)
    print("\n  [1/3] 扫描配置")
    print("  发现 {0} 份配置 · 待更新 {1} 份 · 无需修改 {2} 份 · 跳过 {3} 份".format(
        len(changes), len(pending), len(changes) - len(pending) - skipped_count, skipped_count))
    for item in changes:
        if item.new_text is None and item.notes:
            print("  [跳过] " + item.path)
            for note in item.notes:
                print("         " + note)
    for item in pending:
        print("\n  > [{0}] {1}".format(item.kind, item.path))
        for note in item.notes:
            print("    · " + note)
    for error in errors:
        print("  [跳过] " + error, file=sys.stderr)


def run(args: argparse.Namespace) -> int:
    print("\n  ====================================================")
    print("    代理核心 DNS 配置工具  v{0}".format(VERSION))
    print("  ====================================================")
    print("  模式：{0} · 协议：{1}".format("自动处理" if args.apply else "仅预览", args.protocol))
    print("  流程：扫描 → 检查 → 备份 → 写入 → 重启")
    print("  用法：sh encrypt-proxy-dns.sh | 仅预览加 --dry-run")
    if args.no_check:
        print("  提示：本次已显式关闭核心配置检查。")
    version = singbox_version(args.root)
    changes, errors = plan(args.root, args.protocol, args.paths or None, version)
    print_report(changes, errors, args.apply)
    if not args.apply:
        print("\n  [预览结束] 未写文件、未重启服务。去掉 --dry-run 即可自动处理。")
        return 1 if errors else 0
    kinds: set[str] = set()
    wrote = 0
    print("\n  [2/3] 检查并更新配置")
    for change in changes:
        if change.new_text is None:
            continue
        try:
            ok, info = apply_change(change, args.no_check, args.root)
        except OSError as exc:
            ok, info = False, str(exc)
        if not ok:
            print("  [失败] {0}\n         {1}\n         请检查配置、权限和磁盘空间后重试。".format(change.path, info), file=sys.stderr)
            errors.append(change.path)
            continue
        print("  [已写入] " + change.path)
        print("  [备份]   " + info)
        kinds.add(change.kind)
        wrote += 1
    if not wrote:
        print("  没有写入文件。")
    print("\n  [3/3] 重启服务")
    restarted: list[str] = []
    if args.restart and kinds and os.path.abspath(args.root) == "/":
        restarted, failed = restart_services(kinds)
        for name in restarted:
            print("  [已重启] " + name)
        for failure in failed:
            print("  [重启失败] " + failure + "；请查看服务日志并手动重启。", file=sys.stderr)
        errors.extend(failed)
        if not restarted and not failed:
            print("  未找到正在运行的对应服务；请在目标环境启动服务以加载配置。")
    elif args.restart and kinds and os.path.abspath(args.root) != "/":
        print("  离线根目录：不重启本机服务，请在目标环境加载配置。")
    elif kinds and not args.restart:
        print("  已指定 --no-restart，请手动重启对应服务以加载配置。")
    else:
        print("  没有配置变更，无需重启。")
    print("\n  ----------------------------------------------------")
    print("  {0} · 写入 {1} 份 · 重启 {2} 个服务 · 异常 {3} 项".format(
        "请处理异常后重试" if errors else "本轮处理完成", wrote, len(restarted), len(errors)))
    if not changes:
        print("  未发现支持的配置文件：请确认代理已安装，或在命令后指定配置路径。")
    elif not wrote and not errors:
        print("  本次无配置更新；跳过原因（如有）见扫描结果。")
    if wrote:
        print("  备份已保存至原配置所在目录；需要回退时恢复备份并重启对应服务。")
    print("  ====================================================\n")
    return 1 if errors else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="encrypt-proxy-dns.sh",
        description="代理核心 DNS 配置工具 v" + VERSION + "：默认自动扫描、检查、备份、更新配置并重启对应服务。",
        epilog="运行：sh encrypt-proxy-dns.sh；只预览：sh encrypt-proxy-dns.sh --dry-run。需要 Python 3.9+，修改系统配置通常需要 root。",
    )
    parser.add_argument("--version", action="version", version="代理核心 DNS 配置工具 v" + VERSION)
    write_mode = parser.add_mutually_exclusive_group()
    write_mode.add_argument("--apply", dest="apply", action="store_true", help="自动写入（默认；兼容旧命令）")
    write_mode.add_argument("--dry-run", dest="apply", action="store_false", help="仅预览，不写文件、不重启服务")
    restart_mode = parser.add_mutually_exclusive_group()
    restart_mode.add_argument("--restart", dest="restart", action="store_true", help="写入后重启已运行的对应服务（默认）")
    restart_mode.add_argument("--no-restart", dest="restart", action="store_false", help="写入后不重启服务")
    parser.set_defaults(apply=True, restart=True)
    parser.add_argument("--no-check", action="store_true", help="跳过写入前的核心配置检查")
    parser.add_argument("--protocol", choices=("mixed", "doh", "dot"), default="mixed", help="mixed: Cloudflare DoH、Google DoT、Quad9 DoH")
    parser.add_argument("--root", default="/", help="指定扫描根目录，可用于离线容器文件系统")
    parser.add_argument("--self-test", action="store_true", help="执行内置自检，不修改系统配置")
    parser.add_argument("paths", nargs="*", help="只处理这些文件或目录")
    return parser


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def self_test() -> int:
    mixed = mihomo_endpoints("mixed")
    expect(mixed == [
        "https://1.1.1.1/dns-query",
        "tls://8.8.8.8:853",
        "https://9.9.9.9/dns-query",
    ], "mixed endpoints")
    expect(xray_endpoints(True)[0].startswith("https+local://1.1.1.1/"), "xray local doh")
    expect(all(item.startswith("https://") for item in xray_endpoints(False)), "v2ray doh")

    legacy = {
        "dns": {
            "servers": [
                {"tag": "fake", "address": "fakeip"},
                {"tag": "local", "address": "local"},
                {"tag": "ali", "address": "udp://223.5.5.5", "detour": "direct"},
            ],
            "rules": [
                {"domain_suffix": [".lan"], "server": "local"},
                {"rule_set": "geo-cn", "server": "ali"},
            ],
            "final": "local",
        },
        "outbounds": [
            {"type": "direct", "tag": "direct"},
            {"type": "shadowsocks", "tag": "proxy", "server": "example.com", "domain_resolver": "ali"},
        ],
    }
    notes = rewrite_singbox(legacy, "mixed", (1, 10), True)
    servers = legacy["dns"]["servers"]
    expect(servers[0]["tag"] == "fake" and servers[1]["address"] == "local", "keep fakeip and local")
    expect(servers[2]["address"] == "https://1.1.1.1/dns-query", "legacy doh")
    expect(servers[2]["detour"] == "direct", "legacy detour")
    expect(servers[3]["address"] == "tls://8.8.8.8:853", "legacy dot")
    expect(legacy["dns"]["rules"][0]["server"] == "local", "lan rule stays")
    expect(legacy["dns"]["rules"][1]["server"] == "dns-cloudflare", "public rule retarget")
    expect(legacy["dns"]["final"] == "dns-cloudflare", "final leaves local")
    expect(legacy["outbounds"][1]["domain_resolver"] == "dns-cloudflare", "domain resolver")
    expect(any("223.5.5.5" in note or "ali" in note for note in notes), "notes mention removed")
    again = json.loads(json.dumps(legacy))
    expect(rewrite_singbox(again, "mixed", (1, 10), True) == [] or again == legacy, "legacy idempotent call")
    expect(again == legacy, "legacy second pass stable")

    modern = {
        "dns": {
            "servers": [
                {"type": "fakeip", "tag": "fakeip", "inet4_range": "198.18.0.0/15"},
                {"type": "udp", "tag": "google", "server": "8.8.8.8"},
            ],
            "final": "fakeip",
        },
        "outbounds": [{"type": "direct", "tag": "direct"}],
    }
    rewrite_singbox(modern, "doh", (1, 12), True)
    expect(modern["dns"]["final"] == "fakeip", "fakeip final stays")
    expect(modern["dns"]["servers"][1]["type"] == "https", "new schema doh")
    expect(modern["dns"]["servers"][1]["tls"]["server_name"] == "cloudflare-dns.com", "sni")
    expect(all(item["type"] == "https" for item in modern["dns"]["servers"][1:]), "doh only")

    xray = {
        "dns": {
            "servers": [
                "fakedns",
                "8.8.8.8",
                {"address": "223.5.5.5", "domains": ["geosite:cn"], "port": 53},
                {"address": "10.1.0.1", "domains": ["lan"], "port": 53},
                "localhost",
            ]
        },
        "outbounds": [{"protocol": "freedom", "tag": "direct"}],
    }
    rewrite_xray(xray, True, True)
    expect(xray["dns"]["servers"][0] == "fakedns", "keep fakedns")
    expect(xray["dns"]["servers"][1]["address"] == "10.1.0.1", "keep private")
    expect(xray["dns"]["servers"][2:] == xray_endpoints(True), "three local doh")
    expect("tls://" not in json.dumps(xray), "xray has no dot")
    expect("localhost" not in json.dumps(xray["dns"]["servers"]), "localhost removed")
    snapshot = json.loads(json.dumps(xray))
    expect(rewrite_xray(snapshot, True, True) == [], "xray idempotent")

    v2ray = {"outbounds": [{"protocol": "freedom"}], "inbounds": [{"protocol": "socks"}]}
    rewrite_xray(v2ray, False, True)
    expect(v2ray["dns"]["servers"] == xray_endpoints(False), "v2ray https")

    yaml_text = """
mixed-port: 7890
dns:
  enable: false
  nameserver:
    - 223.5.5.5
    - tls://10.0.0.1:853
  fallback:
    - https://dns.alidns.com/dns-query
  nameserver-policy:
    '+.lan': 10.0.0.1
    "geosite:cn":
      - 119.29.29.29
      - 8.8.8.8
  direct-nameserver: system
proxies:
  - {name: a, type: ss, server: example.com, port: 443}
""".lstrip()
    new_yaml, yaml_notes = rewrite_mihomo_yaml(yaml_text, mixed)
    expect("enable: true" in new_yaml, "enable flipped")
    expect("223.5.5.5" not in new_yaml and "119.29.29.29" not in new_yaml and "alidns" not in new_yaml, "domestic gone")
    expect("tls://10.0.0.1:853" in new_yaml, "private dot kept")
    expect("'+.lan': 10.0.0.1" in new_yaml, "lan scalar kept")
    expect('"geosite:cn":' in new_yaml, "policy key preserved")
    expect(new_yaml.count("https://1.1.1.1/dns-query") >= 3, "cloudflare present")
    expect("default-nameserver:" in new_yaml, "bootstrap added")
    expect("system" not in new_yaml.split("proxies:")[0], "system removed")
    second, second_notes = rewrite_mihomo_yaml(new_yaml, mixed)
    expect(second == new_yaml and second_notes == [], "yaml idempotent: {0}".format(second_notes))
    expect(yaml_notes, "yaml notes")

    bare = "mixed-port: 7890\nproxies:\n  - {name: a, type: ss, server: example.com, port: 1}\n"
    added, added_notes = rewrite_mihomo_yaml(bare, mixed)
    expect("dns:" in added and "enable: true" in added, "dns section created")
    expect(added_notes, "created notes")
    added2, added_notes2 = rewrite_mihomo_yaml(added, mixed)
    expect(added2 == added and added_notes2 == [], "created idempotent")

    commented = """
    {
      // exit
      "outbounds": [{"type": "direct", "tag": "direct"}],
      "dns": {"servers": [{"address": "udp://8.8.8.8",}], "final": "x"}
    }
    """
    cfg = loads_jsonc(commented)
    expect(cfg["dns"]["servers"][0]["address"] == "udp://8.8.8.8", "jsonc")
    text, notes = transform_loaded("sing-box", commented, cfg, "mixed", (1, 11), True)
    expect(text and "https://1.1.1.1/dns-query" in text, "jsonc rewrite")
    expect(any("注释" in note for note in notes), "comment warning")

    with tempfile.TemporaryDirectory() as tmp:
        root = tmp
        paths = {
            "etc/sing-box/config.json": json.dumps(
                {"outbounds": [{"type": "direct", "tag": "direct"}], "dns": {"servers": [{"tag": "a", "address": "8.8.8.8"}]}}
            ),
            "etc/xray/00_in.json": json.dumps({"inbounds": [{"protocol": "socks", "port": 1080}]}),
            "etc/xray/10_out.json": json.dumps({"outbounds": [{"protocol": "freedom", "tag": "direct"}]}),
            "etc/mihomo/config.yaml": "mixed-port: 7890\ndns:\n  enable: true\n  nameserver:\n    - 8.8.8.8\nproxies:\n  - {name: a, type: ss, server: b, port: 1}\n",
            "etc/mosdns/config.yaml": "log:\n  level: info\nplugins:\n  - tag: forward\n    type: forward\n",
            "etc/nginx/nginx.conf": "worker_processes auto;\n",
        }
        for rel, body in paths.items():
            dest = os.path.join(root, rel)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "w", encoding="utf-8") as handle:
                handle.write(body)
        changes, errors = plan(root, "mixed", None, (1, 12))
        expect(not errors, "fixture errors {0}".format(errors))
        by_path = {os.path.relpath(item.path, root): item for item in changes}
        expect(set(by_path) == {
            "etc/sing-box/config.json",
            "etc/xray/00_in.json",
            "etc/xray/10_out.json",
            "etc/mihomo/config.yaml",
        }, "discovery {0}".format(sorted(by_path)))
        expect(by_path["etc/xray/00_in.json"].new_text is None, "inbound snippet untouched")
        expect(by_path["etc/xray/10_out.json"].new_text and "https+local://9.9.9.9/dns-query" in by_path["etc/xray/10_out.json"].new_text, "outbound owns dns")
        expect(
            by_path["etc/sing-box/config.json"].new_text
            and '"address": "https://9.9.9.9/dns-query"' in by_path["etc/sing-box/config.json"].new_text,
            "fixture sing-box",
        )
        expect("114.114.114.114" not in (by_path["etc/mihomo/config.yaml"].new_text or ""), "no domestic default")

    dot = mihomo_endpoints("dot")
    expect(all(item.startswith("tls://") for item in dot) and len(dot) == 3, "dot mode")
    doh = mihomo_endpoints("doh")
    expect(all(item.startswith("https://") for item in doh) and len(doh) == 3, "doh mode")
    print("[自检通过] 代理核心 DNS 配置工具 v" + VERSION + " · 样例全部通过，未修改系统。")
    return 0


def main() -> int:
    if sys.version_info < (3, 9):
        print("需要 Python 3.9 或更新的版本", file=sys.stderr)
        return 1
    args = build_parser().parse_args()
    if args.self_test:
        return self_test()
    return run(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as exc:
        print("self-test failed: {0}".format(exc), file=sys.stderr)
        sys.exit(1)

ENCRYPT_PROXY_DNS_PYTHON
