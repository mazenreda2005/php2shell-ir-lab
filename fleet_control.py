#!/usr/bin/env python3
"""
fleet_control.py — php2shell Incident-Response fleet controller.

One command per response action. Designed so a single node or a whole fleet
is handled the same way ("دوسة واحدة").

Actions
-------
  status      Show every node: live PHP version, tag status, which SG it's in.
  detect      Read each node's running PHP version and flag AFFECTED vs OK
              against the official php2shell patched baselines.
  mitigate    Layer 1 — apply a filtering firewall rule (buy time).
  isolate     Layer 2 — move a node into the quarantine SG (network-cut,
              instance stays alive for forensics). This is "pull from service".
  restore     Undo isolate — move a node back to the normal SG.
  patch       Layer 3 — upgrade the node's PHP to the patched version and
              flip its tags to healthy. The only complete fix.
  hunt        Collect compromise indicators from a node (read-only forensics).
  verify      Re-run detect after patching — proof the fix worked.
  stop|start  Stop/start instances to save money between sessions.

Everything that touches AWS uses YOUR configured credentials (aws configure).
Nothing here enters credentials or runs exploit code.

Usage
-----
  python fleet_control.py status
  python fleet_control.py detect
  python fleet_control.py isolate web-01
  python fleet_control.py patch web-01
  python fleet_control.py verify
  python fleet_control.py stop            # whole fleet
  python fleet_control.py start web-02

Requires: boto3  (pip install boto3). On-box actions (patch/hunt) use ssh with
the key Terraform generated (terraform/php2shell-lab-key.pem).
"""

import argparse
import json
import os
import subprocess
import sys
import urllib.request
from pathlib import Path

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    sys.exit("boto3 is required:  pip install boto3")

# --- Config -----------------------------------------------------------------
FLEET_TAG = os.environ.get("FLEET_NAME", "php2shell-lab")
SSH_KEY = Path(__file__).parent / "terraform" / f"{FLEET_TAG}-key.pem"
SSH_USER = "ubuntu"

# Official php2shell patched baselines (PHP advisory, 21 Oct 2026).
# A node is AFFECTED if its version is below the baseline for its branch.
PATCHED_BASELINE = {
    "8.5": (8, 5, 12),
    "8.4": (8, 4, 27),
    "8.3": (8, 3, 36),
    "8.2": (8, 2, 35),
}

# --- Pretty output ----------------------------------------------------------
class C:
    RED = "\033[91m"; GREEN = "\033[92m"; YEL = "\033[93m"
    BLUE = "\033[94m"; BOLD = "\033[1m"; DIM = "\033[2m"; END = "\033[0m"

def ok(m):   print(f"{C.GREEN}✓{C.END} {m}")
def warn(m): print(f"{C.YEL}▲{C.END} {m}")
def bad(m):  print(f"{C.RED}✗{C.END} {m}")
def info(m): print(f"{C.BLUE}ℹ{C.END} {m}")
def head(m): print(f"\n{C.BOLD}{m}{C.END}")

# --- AWS helpers ------------------------------------------------------------
ec2 = boto3.resource("ec2")
ec2c = boto3.client("ec2")

def _fleet_filter():
    return [{"Name": "tag:Fleet", "Values": [FLEET_TAG]},
            {"Name": "instance-state-name",
             "Values": ["pending", "running", "stopping", "stopped"]}]

def get_nodes():
    """Return {short_name: instance} for every fleet node."""
    nodes = {}
    for inst in ec2.instances.filter(Filters=_fleet_filter()):
        tags = {t["Key"]: t["Value"] for t in (inst.tags or [])}
        name = tags.get("Name", inst.id)
        short = name.replace(f"{FLEET_TAG}-", "")
        nodes[short] = inst
    return dict(sorted(nodes.items()))

def tag_of(inst, key, default=""):
    for t in (inst.tags or []):
        if t["Key"] == key:
            return t["Value"]
    return default

def sg_ids_named(suffix):
    """Resolve a security group id by name suffix (e.g. 'sg', 'quarantine-sg')."""
    name = f"{FLEET_TAG}-{suffix}"
    resp = ec2c.describe_security_groups(
        Filters=[{"Name": "group-name", "Values": [name]}])
    groups = resp.get("SecurityGroups", [])
    if not groups:
        sys.exit(f"Security group '{name}' not found. Did terraform apply run?")
    return groups[0]["GroupId"]

def resolve(selector):
    """selector: a node short-name, or 'all'/None for the whole fleet."""
    nodes = get_nodes()
    if not nodes:
        sys.exit("No fleet nodes found. Run terraform apply first.")
    if selector in (None, "all"):
        return nodes
    if selector not in nodes:
        sys.exit(f"Unknown node '{selector}'. Known: {', '.join(nodes)}")
    return {selector: nodes[selector]}

# --- Version logic ----------------------------------------------------------
def parse_ver(v):
    try:
        return tuple(int(x) for x in v.split(".")[:3])
    except Exception:
        return None

def is_affected(version):
    """True if `version` is below the patched baseline for its branch."""
    t = parse_ver(version)
    if not t:
        return None
    branch = f"{t[0]}.{t[1]}"
    base = PATCHED_BASELINE.get(branch)
    if not base:
        return None
    return t < base

def _mgmt_token():
    """Shared secret written by deploy_sites.py; used to read the real version."""
    f = Path(__file__).parent / "deploy" / ".mgmt_token"
    try:
        return f.read_text().strip()
    except Exception:
        return ""

def live_php_version(inst):
    """Ask the node for its real PHP version via the AUTHENTICATED mgmt endpoint.

    Public pages disclose no version (hardening §5), so detection uses the
    token-protected /mgmt/version.php. Falls back to the legacy /health.php
    (pre-site-deploy nodes) so detection still works before sites are deployed.
    """
    ip = inst.public_ip_address
    if not ip:
        return None
    tok = _mgmt_token()
    if tok:
        try:
            req = urllib.request.Request(f"http://{ip}/mgmt/version.php",
                                         headers={"X-Mgmt-Token": tok})
            with urllib.request.urlopen(req, timeout=5) as r:
                return json.loads(r.read()).get("php")
        except Exception:
            pass
    # Fallback: legacy health endpoint from the initial user_data bootstrap.
    try:
        with urllib.request.urlopen(f"http://{ip}/health.php", timeout=5) as r:
            return json.loads(r.read()).get("php")
    except Exception:
        return None

# --- SSH helper (on-box actions) -------------------------------------------
def ssh(inst, remote_cmd, capture=False):
    ip = inst.public_ip_address
    if not ip:
        sys.exit("Node has no public IP (is it isolated or stopped?).")
    if not SSH_KEY.exists():
        sys.exit(f"SSH key not found at {SSH_KEY}")
    cmd = ["ssh", "-i", str(SSH_KEY),
           "-o", "StrictHostKeyChecking=no",
           "-o", "UserKnownHostsFile=/dev/null",
           "-o", "ConnectTimeout=10",
           f"{SSH_USER}@{ip}", remote_cmd]
    if capture:
        return subprocess.run(cmd, capture_output=True, text=True).stdout
    return subprocess.run(cmd).returncode

# --- Actions ----------------------------------------------------------------
def action_status(sel):
    head(f"Fleet: {FLEET_TAG}")
    print(f"{C.DIM}{'NODE':<10}{'STATE':<10}{'PHP (live)':<12}"
          f"{'TAG':<10}{'SG':<14}PUBLIC IP{C.END}")
    for name, inst in resolve(sel).items():
        state = inst.state["Name"]
        live = live_php_version(inst) or "-"
        tagv = tag_of(inst, "PHPVersion", "-")
        sgs = [g["GroupName"].replace(f"{FLEET_TAG}-", "") for g in inst.security_groups]
        sg = ",".join(sgs) or "-"
        ip = inst.public_ip_address or "-"
        line = f"{name:<10}{state:<10}{live:<12}{tagv:<10}{sg:<14}{ip}"
        print(line)

def action_detect(sel):
    head("Detection — php2shell exposure (version-based)")
    any_affected = False
    for name, inst in resolve(sel).items():
        ver = live_php_version(inst) or tag_of(inst, "PHPVersion")
        aff = is_affected(ver)
        if aff is True:
            any_affected = True
            bad(f"{name:<10} PHP {ver:<10} AFFECTED (below patched baseline)")
        elif aff is False:
            ok(f"{name:<10} PHP {ver:<10} OK (patched)")
        else:
            warn(f"{name:<10} PHP {ver or '?':<10} UNKNOWN (could not determine)")
    print()
    (bad if any_affected else ok)(
        "One or more nodes AFFECTED — respond now." if any_affected
        else "No affected nodes detected.")
    return any_affected

def action_isolate(sel):
    q = sg_ids_named("quarantine-sg")
    for name, inst in resolve(sel).items():
        inst.modify_attribute(Groups=[q])
        ec2c.create_tags(Resources=[inst.id],
                         Tags=[{"Key": "Status", "Value": "isolated"}])
        warn(f"{name} ISOLATED — moved to quarantine SG (network cut, host alive).")

def action_restore(sel):
    normal = sg_ids_named("sg")
    for name, inst in resolve(sel).items():
        inst.modify_attribute(Groups=[normal])
        ok(f"{name} restored to normal SG.")

def action_mitigate(sel):
    head("Layer 1 — Mitigation (temporary request filtering)")
    info("Applying a stop-gap firewall rule on each node to drop suspicious "
         "upload-progress requests while remediation runs.")
    rule = (
        "sudo iptables -I INPUT -p tcp --dport 80 "
        "-m string --algo bm --string 'session.upload_progress' -j DROP "
        "&& echo RULE_APPLIED || echo RULE_SKIPPED")
    for name, inst in resolve(sel).items():
        out = ssh(inst, rule, capture=True)
        if "RULE_APPLIED" in out:
            ok(f"{name}: mitigation rule applied.")
        else:
            warn(f"{name}: could not apply rule (node may be isolated/stopped).")

def action_patch(sel):
    head("Layer 3 — Remediation (patch PHP to the fixed version)")
    for name, inst in resolve(sel).items():
        cur = live_php_version(inst) or tag_of(inst, "PHPVersion")
        t = parse_ver(cur)
        if not t:
            warn(f"{name}: unknown current version, skipping.")
            continue
        branch = f"{t[0]}.{t[1]}"
        base = PATCHED_BASELINE.get(branch)
        if not base:
            warn(f"{name}: no known baseline for branch {branch}, skipping.")
            continue
        target = ".".join(str(x) for x in base)
        if not is_affected(cur):
            ok(f"{name}: already on {cur} (patched). Nothing to do.")
            continue
        info(f"{name}: {cur} → {target} (rebuilding container on patched image)…")
        tok = _mgmt_token()
        # Re-create on the patched image, preserving the deployed site, the
        # hardening mounts, and the mgmt token (if the node has them).
        harden = ""
        if tok:
            harden = (
                "-v /opt/hardening/php-hardening.ini:/usr/local/etc/php/conf.d/zz-hardening.ini:ro "
                "-v /opt/hardening/apache-hardening.conf:/etc/apache2/conf-enabled/zz-hardening.conf:ro "
                f"-e MGMT_TOKEN={tok} ")
        remote = (
            f"sudo docker pull php:{target}-apache && "
            f"sudo docker rm -f webserver && "
            f"sudo docker run -d --name webserver --restart unless-stopped "
            f"-p 80:80 -v /opt/webapp:/var/www/html {harden}php:{target}-apache && "
            f"sudo docker exec webserver a2enmod headers rewrite >/dev/null 2>&1 || true; "
            f"sudo docker exec webserver apache2ctl graceful >/dev/null 2>&1 || true; "
            f"echo {target} | sudo tee /opt/php_deployed_version.txt")
        rc = ssh(inst, remote)
        if rc == 0:
            ec2c.create_tags(Resources=[inst.id], Tags=[
                {"Key": "PHPVersion", "Value": target},
                {"Key": "Status", "Value": "healthy"}])
            ok(f"{name}: patched to {target} and tags updated to healthy.")
        else:
            bad(f"{name}: patch command failed (check SSH / node reachability).")

def action_hunt(sel):
    head("Hunt — read-only compromise indicators")
    checks = (
        "echo '--- recent web-root changes (48h) ---'; "
        "find /opt/webapp -type f -mtime -2 -printf '%t %p\\n' 2>/dev/null; "
        "echo '--- unexpected .php files ---'; "
        "ls -la /opt/webapp/*.php 2>/dev/null; "
        "echo '--- listening sockets ---'; "
        "sudo ss -tulpn 2>/dev/null | grep -v ':80 ' ; "
        "echo '--- container processes ---'; "
        "docker top webserver 2>/dev/null; "
        "echo '--- last logins ---'; last -n 5 2>/dev/null")
    for name, inst in resolve(sel).items():
        print(f"\n{C.BOLD}[{name}]{C.END}")
        out = ssh(inst, checks, capture=True)
        print(out or "  (no output / node unreachable)")

def action_verify(sel):
    head("Verification — re-running detection after remediation")
    affected = action_detect(sel)
    print()
    if affected:
        bad("Verification FAILED — still affected nodes.")
    else:
        ok("Verification PASSED — fleet is no longer affected. Proof complete.")

def action_power(sel, on):
    for name, inst in resolve(sel).items():
        if on:
            inst.start(); ok(f"{name}: starting.")
        else:
            inst.stop(); warn(f"{name}: stopping (saves money).")

# --- CLI --------------------------------------------------------------------
def main():
    p = argparse.ArgumentParser(
        description="php2shell Incident-Response fleet controller",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("action", choices=[
        "status", "detect", "mitigate", "isolate", "restore",
        "patch", "hunt", "verify", "stop", "start"])
    p.add_argument("node", nargs="?", default="all",
                   help="node short-name (e.g. web-01) or 'all' (default)")
    args = p.parse_args()

    a, n = args.action, args.node
    if a == "status":     action_status(n)
    elif a == "detect":   action_detect(n)
    elif a == "mitigate": action_mitigate(n)
    elif a == "isolate":  action_isolate(n)
    elif a == "restore":  action_restore(n)
    elif a == "patch":    action_patch(n)
    elif a == "hunt":     action_hunt(n)
    elif a == "verify":   action_verify(n)
    elif a == "stop":     action_power(n, on=False)
    elif a == "start":    action_power(n, on=True)

if __name__ == "__main__":
    main()
