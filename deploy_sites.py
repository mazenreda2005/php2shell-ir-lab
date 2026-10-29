#!/usr/bin/env python3
"""
deploy_sites.py — deploy the three NovaEdge websites + hardening onto the fleet.

For each node it:
  1. Stages the node's site (web-01/02/03) + shared assets, mgmt endpoint,
     public health check, and PHP/Apache hardening configs.
  2. Ships the payload over SSH (tar stream — no extra tools needed).
  3. Recreates the Docker container on the node's current PHP version
     (read live from the PHPVersion tag) with:
       - hardening ini/conf mounted,
       - an injected MGMT_TOKEN (for the authenticated version endpoint),
       - mod_headers / mod_rewrite enabled and Apache reloaded.

The MGMT_TOKEN is generated once and stored in deploy/.mgmt_token so that
fleet_control.py can authenticate to /mgmt/version.php for detection.

Usage:
  python deploy_sites.py              # deploy all three
  python deploy_sites.py web-01       # deploy one node
  python deploy_sites.py --check      # just SSH-ping each node (no changes)

Requires: boto3, and `ssh` available on PATH (Windows 10+ has it built in).
"""
import os, sys, secrets, subprocess, tarfile, io, json
from pathlib import Path

try:
    import boto3
except ImportError:
    sys.exit("boto3 is required:  pip install boto3")

ROOT = Path(__file__).parent
SITES = ROOT / "sites"
SHARED = SITES / "shared"
KEY = ROOT / "terraform" / "php2shell-lab-key.pem"
FLEET_TAG = os.environ.get("FLEET_NAME", "php2shell-lab")
SSH_USER = "ubuntu"

NODE_SITE = {
    "web-01": "web-01-corporate",
    "web-02": "web-02-portal",
    "web-03": "web-03-status",
}

# --- token shared with fleet_control for authenticated version checks ---
TOKEN_FILE = ROOT / "deploy" / ".mgmt_token"
def get_token() -> str:
    TOKEN_FILE.parent.mkdir(exist_ok=True)
    if TOKEN_FILE.exists():
        return TOKEN_FILE.read_text().strip()
    tok = secrets.token_hex(24)
    TOKEN_FILE.write_text(tok)
    try: os.chmod(TOKEN_FILE, 0o600)
    except Exception: pass
    return tok

# --- AWS: discover nodes ---
ec2 = boto3.resource("ec2")
def nodes():
    out = {}
    f = [{"Name": "tag:Fleet", "Values": [FLEET_TAG]},
         {"Name": "instance-state-name", "Values": ["running"]}]
    for inst in ec2.instances.filter(Filters=f):
        tags = {t["Key"]: t["Value"] for t in (inst.tags or [])}
        short = tags.get("Name", "").replace(f"{FLEET_TAG}-", "")
        out[short] = {"ip": inst.public_ip_address,
                      "php": tags.get("PHPVersion", "8.2.35")}
    return out

def ssh_base(ip):
    return ["ssh", "-i", str(KEY), "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=12",
            f"{SSH_USER}@{ip}"]

def ssh_run(ip, cmd, stdin=None):
    return subprocess.run(ssh_base(ip) + [cmd], input=stdin,
                          capture_output=True)

def build_payload(node) -> bytes:
    """tar.gz of everything that goes to /opt/webapp on the node, plus hardening."""
    site_dir = SITES / NODE_SITE[node]
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        # site files -> webapp/
        for p in site_dir.rglob("*"):
            if p.is_file():
                tar.add(p, arcname=f"webapp/{p.relative_to(site_dir)}")
        # shared assets/mgmt/health -> webapp/
        tar.add(SHARED / "theme.css", arcname="webapp/assets/theme.css")
        tar.add(SHARED / "mgmt" / "version.php", arcname="webapp/mgmt/version.php")
        tar.add(SHARED / "health.php", arcname="webapp/health.php")
        # hardening -> hardening/
        tar.add(SHARED / "hardening" / "php-hardening.ini", arcname="hardening/php-hardening.ini")
        tar.add(SHARED / "hardening" / "apache-hardening.conf", arcname="hardening/apache-hardening.conf")
    return buf.getvalue()

REMOTE_DEPLOY = """
set -e
sudo rm -rf /opt/webapp /opt/hardening
sudo mkdir -p /opt/webapp /opt/hardening
sudo tar xzf /tmp/payload.tgz -C /tmp/_stage 2>/dev/null || (mkdir -p /tmp/_stage && sudo tar xzf /tmp/payload.tgz -C /tmp/_stage)
sudo cp -r /tmp/_stage/webapp/. /opt/webapp/
sudo cp -r /tmp/_stage/hardening/. /opt/hardening/
sudo rm -rf /tmp/_stage /tmp/payload.tgz

sudo docker rm -f webserver 2>/dev/null || true
sudo docker run -d --name webserver --restart unless-stopped -p 80:80 \
  -v /opt/webapp:/var/www/html \
  -v /opt/hardening/php-hardening.ini:/usr/local/etc/php/conf.d/zz-hardening.ini:ro \
  -v /opt/hardening/apache-hardening.conf:/etc/apache2/conf-enabled/zz-hardening.conf:ro \
  -e MGMT_TOKEN=__TOKEN__ \
  php:__PHP__-apache

# enable modules the hardening/app rely on, then reload
sudo docker exec webserver a2enmod headers rewrite >/dev/null 2>&1 || true
sudo docker exec webserver mkdir -p /var/www/private && sudo docker exec webserver chown www-data:www-data /var/www/private || true
sudo docker exec webserver apache2ctl graceful >/dev/null 2>&1 || sudo docker restart webserver >/dev/null
echo DEPLOY_OK
"""

def deploy(node, info, token):
    ip = info["ip"]; php = info["php"]
    print(f"→ {node} ({ip}) · PHP {php} · site {NODE_SITE[node]}")
    payload = build_payload(node)
    # ship payload
    up = subprocess.run(ssh_base(ip) + ["cat > /tmp/payload.tgz"], input=payload,
                        capture_output=True)
    if up.returncode != 0:
        print(f"  ✗ upload failed: {up.stderr.decode().strip()[:200]}"); return False
    script = REMOTE_DEPLOY.replace("__TOKEN__", token).replace("__PHP__", php)
    r = ssh_run(ip, script)
    out = (r.stdout + r.stderr).decode(errors="replace")
    if "DEPLOY_OK" in out:
        print(f"  ✓ deployed. http://{ip}/")
        return True
    print(f"  ✗ deploy failed:\n{out[-500:]}"); return False

def check(node, info):
    r = ssh_run(info["ip"], "echo SSH_OK && sudo docker ps --format '{{.Names}}' 2>/dev/null")
    out = (r.stdout + r.stderr).decode(errors="replace")
    print(f"{'✓' if 'SSH_OK' in out else '✗'} {node} ({info['ip']}): "
          + ("reachable" if 'SSH_OK' in out else out.strip()[:160]))

def main():
    args = [a for a in sys.argv[1:]]
    only_check = "--check" in args
    targets = [a for a in args if not a.startswith("--")]
    fleet = nodes()
    if not fleet: sys.exit("No running fleet nodes found. Run terraform apply first.")
    if targets:
        fleet = {k: v for k, v in fleet.items() if k in targets}
    if only_check:
        for n, i in sorted(fleet.items()): check(n, i)
        return
    token = get_token()
    print(f"Using mgmt token from {TOKEN_FILE} (shared with fleet_control for detection).\n")
    results = {}
    for n, i in sorted(fleet.items()):
        if n not in NODE_SITE:
            print(f"– skipping {n} (no site mapping)"); continue
        results[n] = deploy(n, i, token)
    print("\nSummary:", ", ".join(f"{k}={'ok' if v else 'FAIL'}" for k, v in results.items()))

if __name__ == "__main__":
    main()
