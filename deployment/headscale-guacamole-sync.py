#!/usr/bin/env python3
"""
Headscale-Guacamole Auto-Sync

Automatically synchronizes Headscale nodes with Apache Guacamole connections.
Scans for open ports (SSH, RDP, VNC) and creates/removes connections accordingly.

Part of IceLaborVPN - https://github.com/icepaule/IceLaborVPN

Usage:
    1. Configure the variables below
    2. Run manually: python3 headscale-guacamole-sync.py
    3. Or set up as cron job: */5 * * * * /usr/bin/python3 /path/to/headscale-guacamole-sync.py

Requirements:
    - Headscale CLI accessible (sudo -u headscale headscale ...)
    - Docker with Guacamole PostgreSQL container
    - Python 3.6+
"""

import json
import socket
import subprocess
import sys
from datetime import datetime

# === CONFIGURATION - MODIFY THESE VALUES ===
CONFIG = {
    # Guacamole connection defaults
    "default_username": "admin",           # Default SSH/RDP username
    "ssh_color_scheme": "green-black",     # SSH terminal color scheme
    "ssh_font_size": "14",
    "ssh_scrollback": "10000",
    "rdp_color_depth": "24",
    "rdp_security": "any",                 # any, nla, tls, rdp
    "rdp_ignore_cert": "true",
    "vnc_color_depth": "24",
    
    # Scanning
    "scan_timeout": 1,                     # Port scan timeout in seconds
    
    # Guacamole
    "admin_entity": "admin",               # Guacamole user for permissions
    "docker_db_container": "guacamole-db", # PostgreSQL container name
    "db_user": "guacamole",
    "db_name": "guacamole",
    
    # Headscale
    "headscale_config": "/etc/headscale/config.yaml",
    "headscale_user": "headscale",
    
    # Nodes to skip (e.g., the gateway itself)
    "skip_nodes": ["headscale-gw"],
}

PROTOCOLS = {
    "ssh": {"port": 22, "name": "SSH"},
    "rdp": {"port": 3389, "name": "RDP"},
    "vnc": {"port": 5900, "name": "VNC"},
}
# ============================================


def log(msg):
    """Logging with timestamp."""
    print(f"[{datetime.now().isoformat()}] {msg}")


def run_cmd(cmd, check=True):
    """Execute shell command and return output."""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and result.returncode != 0:
        log(f"ERROR: {cmd}")
        log(f"STDERR: {result.stderr}")
        return None
    return result.stdout.strip()


def get_headscale_nodes():
    """Retrieve all Headscale nodes."""
    cmd = f"sudo -u {CONFIG['headscale_user']} headscale -c {CONFIG['headscale_config']} nodes list -o json"
    output = run_cmd(cmd)
    if not output:
        return []
    try:
        return json.loads(output)
    except json.JSONDecodeError as e:
        log(f"JSON parse error: {e}")
        return []


def scan_port(ip, port, timeout=1):
    """Check if a port is open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def db_query(sql, fetch=True):
    """Execute SQL query on Guacamole database."""
    escaped_sql = sql.replace("'", "'\"'\"'")
    cmd = f"docker exec {CONFIG['docker_db_container']} psql -U {CONFIG['db_user']} -d {CONFIG['db_name']} -t -c '{escaped_sql}'"
    output = run_cmd(cmd, check=False)
    if output is None:
        return [] if fetch else False
    if not fetch:
        return True
    lines = [line.strip() for line in output.split("\n") if line.strip()]
    return lines


def get_guacamole_connections():
    """Retrieve all Guacamole connections."""
    rows = db_query("SELECT connection_id, connection_name, protocol FROM guacamole_connection")
    connections = {}
    for row in rows:
        parts = [p.strip() for p in row.split("|")]
        if len(parts) >= 3:
            conn_id, name, protocol = parts[0], parts[1], parts[2]
            connections[name] = {"id": int(conn_id), "protocol": protocol}
    return connections


def get_admin_entity_id():
    """Get the entity ID of the admin user."""
    rows = db_query(f"SELECT entity_id FROM guacamole_entity WHERE name = '{CONFIG['admin_entity']}'")
    if rows:
        return int(rows[0].strip())
    return None


def create_connection(hostname, protocol, ip, port):
    """Create a new Guacamole connection."""
    conn_name = f"{hostname} ({PROTOCOLS[protocol]['name']})"
    log(f"Creating connection: {conn_name}")
    
    result = db_query(
        f"INSERT INTO guacamole_connection (connection_name, protocol) "
        f"VALUES ('{conn_name}', '{protocol}') RETURNING connection_id"
    )
    if not result:
        log(f"ERROR: Could not create connection: {conn_name}")
        return False
    
    conn_id = int(result[0].strip())
    
    # Base parameters
    params = [
        (conn_id, "hostname", ip),
        (conn_id, "port", str(port)),
    ]
    
    # Protocol-specific parameters
    if protocol == "ssh":
        params.extend([
            (conn_id, "username", CONFIG["default_username"]),
            (conn_id, "color-scheme", CONFIG["ssh_color_scheme"]),
            (conn_id, "font-size", CONFIG["ssh_font_size"]),
            (conn_id, "scrollback", CONFIG["ssh_scrollback"]),
        ])
    elif protocol == "rdp":
        params.extend([
            (conn_id, "username", CONFIG["default_username"]),
            (conn_id, "security", CONFIG["rdp_security"]),
            (conn_id, "ignore-cert", CONFIG["rdp_ignore_cert"]),
            (conn_id, "color-depth", CONFIG["rdp_color_depth"]),
        ])
    elif protocol == "vnc":
        params.extend([
            (conn_id, "color-depth", CONFIG["vnc_color_depth"]),
        ])
    
    # Insert parameters
    for conn_id, param_name, param_value in params:
        db_query(
            f"INSERT INTO guacamole_connection_parameter (connection_id, parameter_name, parameter_value) "
            f"VALUES ({conn_id}, '{param_name}', '{param_value}')",
            fetch=False
        )
    
    # Set permissions
    admin_id = get_admin_entity_id()
    if admin_id:
        for perm in ["READ", "UPDATE", "DELETE", "ADMINISTER"]:
            db_query(
                f"INSERT INTO guacamole_connection_permission (entity_id, connection_id, permission) "
                f"VALUES ({admin_id}, {conn_id}, '{perm}'::guacamole_object_permission_type)",
                fetch=False
            )
    
    log(f"Connection created: {conn_name} (ID: {conn_id})")
    return True


def delete_connection(conn_id, conn_name):
    """Delete a Guacamole connection."""
    log(f"Deleting connection: {conn_name} (ID: {conn_id})")
    
    db_query(f"DELETE FROM guacamole_connection_permission WHERE connection_id = {conn_id}", fetch=False)
    db_query(f"DELETE FROM guacamole_connection_parameter WHERE connection_id = {conn_id}", fetch=False)
    db_query(f"DELETE FROM guacamole_connection WHERE connection_id = {conn_id}", fetch=False)
    
    log(f"Connection deleted: {conn_name}")


def sync():
    """Main synchronization."""
    log("=== Starting Headscale-Guacamole Sync ===")
    
    nodes = get_headscale_nodes()
    connections = get_guacamole_connections()
    
    log(f"Found: {len(nodes)} Headscale nodes, {len(connections)} Guacamole connections")
    
    expected_connections = set()
    
    for node in nodes:
        hostname = node.get("name", "")
        online = node.get("online", False)
        ip_addresses = node.get("ip_addresses", [])
        
        if not hostname or not ip_addresses:
            continue
        
        if hostname in CONFIG["skip_nodes"]:
            log(f"Skipping node: {hostname}")
            continue
        
        ip = ip_addresses[0]
        
        if not online:
            log(f"Node offline: {hostname}")
            continue
        
        log(f"Checking node: {hostname} ({ip})")
        
        for protocol, info in PROTOCOLS.items():
            port = info["port"]
            conn_name = f"{hostname} ({info['name']})"
            
            if scan_port(ip, port, CONFIG["scan_timeout"]):
                log(f"  Port {port} ({protocol}) open")
                expected_connections.add(conn_name)
                
                if conn_name not in connections:
                    create_connection(hostname, protocol, ip, port)
            else:
                log(f"  Port {port} ({protocol}) closed")
    
    # Remove connections for offline/removed nodes
    for conn_name, conn_info in connections.items():
        is_headscale_conn = any(
            conn_name.startswith(f"{node.get('name', '')} (") 
            for node in nodes 
            if node.get('name') not in CONFIG["skip_nodes"]
        )
        
        if is_headscale_conn and conn_name not in expected_connections:
            delete_connection(conn_info["id"], conn_name)
    
    log("=== Sync completed ===\n")


if __name__ == "__main__":
    try:
        sync()
    except Exception as e:
        log(f"FATAL ERROR: {e}")
        sys.exit(1)
