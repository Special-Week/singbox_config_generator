import base64
import json
import socket
from pathlib import Path
from typing import Dict, List
from urllib.parse import unquote

CURRENT_PATH = Path(__file__).parent
node_count = 0
port_start = 40000


def decode_vless(node: str) -> Dict:
    global node_count
    node_count += 1
    node = node.replace("vless://", "")
    uuid = node.split("@")[0]
    node = node.replace(f"{uuid}@", "")
    address = node.split(":")[0]
    node = node.replace(f"{address}:", "")
    port = node.split("?")[0]
    node = node.replace(f"{port}?", "")
    remarks = node.split("#")[-1]
    node = node.replace(f"#{remarks}", "")
    remarks = unquote(remarks).strip()
    param = node.split("&")
    param_dict = {}
    for item in param:
        key, value = item.split("=")
        param_dict[key] = value
    flow = param_dict.get("flow")
    security = param_dict.get("security")
    sni = param_dict.get("sni")
    fingerprint = param_dict.get("fp")
    type_ = param_dict.get("type")
    path = param_dict.get("path")
    if path:
        path = unquote(path)
    host = param_dict.get("host")

    result = {
        "type": "vless",
        "tag": f"out_bound_{node_count}_{remarks}",
        "server": address,
        "server_port": int(port),
        "uuid": uuid,
        "packet_encoding": "xudp",
        "tls": {
            "enabled": True,
            "server_name": sni,
            "insecure": False,
            "utls": {"enabled": True, "fingerprint": fingerprint},
        },
    }
    if security == "reality":
        public_key = param_dict.get("pbk")
        short_id = param_dict.get("sid")
        result["tls"]["reality"] = {
            "enabled": True,
            "public_key": public_key,
            "short_id": short_id,
        }
        result["flow"] = flow
    elif security == "tls":
        if type_ == "ws":
            result["transport"] = {
                "type": type_,
                "path": path,
                "headers": {"Host": host},
            }
        elif type_ == "tcp":
            result["flow"] = flow

    return result


def decode_vmess(node: str) -> Dict:
    global node_count
    node_count += 1
    node = node.replace("vmess://", "")
    node = base64.b64decode(node).decode()
    node_info: Dict = json.loads(node)
    remarks = node_info["ps"]

    return {
        "type": "vmess",
        "tag": f"out_bound_{node_count}_{remarks}",
        "server": node_info["add"],
        "server_port": int(node_info["port"]),
        "uuid": node_info["id"],
        "security": node_info["scy"],
        "alter_id": int(node_info["aid"]),
    }


def decode_ss(node: str) -> Dict:
    global node_count
    node_count += 1
    node = node.replace("ss://", "")
    remarks = node.split("#")[-1]
    node = node.replace(f"#{remarks}", "")
    remarks = unquote(remarks).strip()
    port = node.split(":")[-1]
    node = node.replace(f":{port}", "")
    address = node.split("@")[-1]
    node = node.replace(f"@{address}", "")
    node = base64.b64decode(node).decode()
    method, password = node.split(":")
    return {
        "type": "shadowsocks",
        "tag": f"out_bound_{node_count}_{remarks}",
        "server": address,
        "server_port": int(port),
        "method": method,
        "password": password,
    }


def decode_trojan(node: str) -> Dict:
    global node_count
    node_count += 1
    node = node.replace("trojan://", "")
    password = node.split("@")[0]
    node = node.replace(f"{password}@", "")
    address = node.split(":")[0]
    node = node.replace(f"{address}:", "")
    port = node.split("?")[0]
    node = node.replace(f"{port}?", "")
    remarks = node.split("#")[-1]
    node = node.replace(f"#{remarks}", "")
    remarks = unquote(remarks).strip()
    param = node.split("&")
    param_dict = {}
    for item in param:
        key, value = item.split("=")
        param_dict[key] = value
    sni = param_dict.get("sni")

    return {
        "type": "trojan",
        "tag": f"out_bound_{node_count}_{remarks}",
        "server": address,
        "server_port": int(port),
        "password": password,
        "tls": {
            "enabled": True,
            "server_name": sni,
            "insecure": False,
        },
    }


def decode_hysteria2(node: str) -> Dict:
    global node_count
    node_count += 1
    node = node.replace("hysteria2://", "")
    password = node.split("@")[0]
    node = node.replace(f"{password}@", "")
    remarks = unquote(node.split("#")[-1]).strip()
    node = node.replace(f"#{remarks}", "")
    host_port, para_dict = node.split("?")
    server, port = host_port.split(":")
    param_dict = {}
    for item in para_dict.split("&"):
        key, value = item.split("=")
        param_dict[key] = value
    sni = param_dict.get("sni")
    insecure = param_dict.get("insecure")
    return {
        "type": "hysteria2",
        "tag": f"out_bound_{node_count}_{remarks}",
        "server": server,
        "server_port": int(port),
        "password": password,
        "tls": {
            "enabled": True,
            "server_name": sni,
            "insecure": bool(insecure),
        },
    }


def read_node() -> List[Dict]:
    outbounds: List[Dict] = []
    with open(CURRENT_PATH / "node.txt", "r", encoding="utf-8") as f:
        for item in f:
            if item.startswith("vless://"):
                outbounds.append(decode_vless(item))
            elif item.startswith("vmess://"):
                outbounds.append(decode_vmess(item))
            elif item.startswith("ss://"):
                outbounds.append(decode_ss(item))
            elif item.startswith("trojan://"):
                outbounds.append(decode_trojan(item))
            elif item.startswith("hysteria2://"):
                outbounds.append(decode_hysteria2(item))

    return outbounds


def set_inbounds(outbounds: List[Dict]) -> List[Dict]:
    global port_start
    inbounds = []
    port_start = find_free_ports(40000, len(outbounds))
    port = port_start
    for port, item in enumerate(outbounds, start=port):
        tag: str = item["tag"]
        inbounds.append(
            {
                "type": "http",
                "tag": tag.replace("out_bound", "in_bound"),
                "listen": "127.0.0.1",
                "listen_port": port,
                "sniff": True,
                "sniff_override_destination": True,
            }
        )
    return inbounds


def set_routing(in_bound) -> Dict:
    rules = []
    for item in in_bound:
        tag: str = item["tag"]
        rules.append(
            {
                "inbound": tag,
                "outbound": tag.replace("in_bound", "out_bound"),
            }
        )
    return {"rules": rules}


def find_free_ports(start_range, num_ports=1) -> int:
    def port_is_free(port) -> bool:
        temp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            temp_socket.bind(("localhost", port))
            return True
        except socket.error:
            return False
        finally:
            temp_socket.close()

    count = 0
    port = start_range
    while count < num_ports:
        if port_is_free(port):
            count += 1
        else:
            count = 0
        port += 1
    return port - num_ports


if __name__ == "__main__":
    outbounds = read_node()
    inbounds = set_inbounds(outbounds)
    routing = set_routing(inbounds)
    config = {
        "log": {"level": "info", "timestamp": True},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": routing,
    }
    with open(CURRENT_PATH / "config.json", "w", encoding="utf-8") as f:
        json.dump(config, f, indent=4, ensure_ascii=False)
    print(
        f"singbox config.json已生成，端口起始位置: {port_start}, 共{len(outbounds)}个节点"
    )
