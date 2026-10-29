# php2shell Incident-Response Lab

A hands-on **cloud incident-response** project built on AWS. It simulates a real
company fleet reacting to the **php2shell** emergency (CVE-2026-109618 /
CVE-2026-109619 — unauthenticated RCE in PHP, disclosed 21 Oct 2026) and
demonstrates the full response lifecycle **detect → contain → remediate →
verify**, with the containment step fully **automated**.

Everything is **Infrastructure as Code** (Terraform) and runs on a single-digit
dollar budget using AWS free-tier credits.

![Architecture](docs/architecture.png)

---

## The scenario

On 21 October 2026, the PHP project shipped emergency fixes (8.5.12 / 8.4.27 /
8.3.36 / **8.2.35**) for two critical flaws collectively called **php2shell**,
after the FBI/CISA urged organisations to *inventory PHP, prioritise
internet-facing systems, and patch*. This lab plays the role of the security
engineer responsible for a small company's fleet during that event.

| CVE | Type | Baseline (fixed in) |
|-----|------|---------------------|
| CVE-2026-109618 | OOM memory corruption → RCE | 8.2.35 (for the 8.2 branch) |
| CVE-2026-109619 | stale global state → RCE | 8.2.35 (for the 8.2 branch) |

> **Scope & ethics.** This lab proves exposure by **authoritative version
> comparison**, not by running exploit code. There is no weaponised PoC in this
> repository, and automatic exploitation is never wired into the detector or the
> response Lambda. See [`proof/README.md`](proof/README.md).

---

## The fleet

Three `t3.micro` EC2 nodes, each running PHP as a **pinned Docker image**
(`php:<ver>-apache` = Apache + mod_php, the most exposed configuration in the
advisory). Each carries `PHPVersion` / `Status` tags that are the signal the
automation watches.

| Node | Role | PHP | State |
|------|------|-----|-------|
| `web-01` | **NovaEdge** corporate website | 8.2.20 → 8.2.35 | vulnerable → remediated |
| `web-02` | **NovaEdge** customer portal (login, tickets, requests) | 8.2.35 | healthy |
| `web-03` | **NovaEdge** service-status page | 8.2.35 | healthy |

All three are real, functional PHP applications sharing one corporate brand, with
fictional data only. Access is locked to the operator's own IP; the quarantine
security group has **no inbound** and is used for isolation.

---

## Incident-response workflow

Each response action is **one command** via `fleet_control.py` (a node or the
whole fleet), and the containment layer also runs automatically.

1. **Detect** — read each node's real PHP version from an **authenticated**
   management endpoint and compare to the official patched baseline.
2. **Mitigate** *(layer 1)* — stop-gap request filtering (buy time).
3. **Isolate** *(layer 2)* — move the node onto the quarantine SG: network-cut,
   host preserved for forensics.
4. **Remediate** *(layer 3)* — rebuild the container on the patched PHP image and
   flip the tags to healthy.
5. **Verify** — re-run detection; the same tool that proved exposure proves the
   fix.

### Demonstrated end-to-end (real run)

```
detect   →  web-01  PHP 8.2.20  AFFECTED
automated response fires (EventBridge → Lambda):
         →  web-01 isolated, verified, evidence written to S3, email alert sent
remediate→  web-01 patched to 8.2.35
verify   →  web-01/02/03 all OK — "Verification PASSED"
```

---

## Automated incident response (SOAR)

`EventBridge (every 5 min) → Lambda → { isolate, SNS alert, S3 evidence,
CloudWatch logs }`, on a **least-privilege IAM role** scoped by the `Fleet` tag.

The Lambda classifies each node as **AFFECTED / PATCHED / UNKNOWN**, never infers
compromise from a vulnerable version alone, de-duplicates already-isolated nodes,
collects evidence **before** containment, isolates the node, **verifies** the
resulting security-group membership, and only then reports the real result.
Auto-containment is configurable (`auto_contain`).

---

## Hardening (information disclosure)

- `expose_php = Off`, `ServerTokens Prod`, `ServerSignature Off`
- generic public error pages; no PHP stack traces in production
- sensitive files (`.ini`, `.log`, `.pem`, …) blocked at the web server
- the real PHP version is served only from a **token-authenticated**
  `/mgmt/version.php`, kept separate from the public (version-free) health check

---

## Quick start

```bash
cd terraform
terraform init
terraform apply                      # builds the fleet + automation
cd ..
python deploy_sites.py               # deploy the 3 websites + hardening
python fleet_control.py status       # see the fleet
```

Settings live in `terraform/terraform.tfvars` (allowed IP range, alert email,
automation toggles). Confirm the SNS subscription email after the first apply.

## Cost & teardown

`t3.micro` + short sessions ≈ a few dollars, covered by free-tier credits. Stop
between sessions and destroy when done:

```bash
python fleet_control.py stop         # pause compute cost
terraform destroy                    # remove everything
```

## Project layout

```
terraform/        IaC: fleet, security groups, IAM, Lambda, EventBridge, SNS, S3
lambda/           detector_responder.py — the automated responder
sites/            web-01/02/03 PHP apps + shared theme, hardening, mgmt endpoint
fleet_control.py  operator CLI (status/detect/mitigate/isolate/patch/hunt/verify)
deploy_sites.py   push apps + hardening to the fleet over SSH
proof/            exposure-verification methodology (no exploit code)
docs/             architecture diagram and documentation
```

## Sources

- PHP security advisory, 21 Oct 2026 — patched versions 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35
- FBI/CISA guidance: inventory PHP, prioritise internet-facing systems, patch
- CERT-EU Advisory 2026-018; vendor write-ups (Sophos, Fortinet, Wiz, watchTowr, Recorded Future)
