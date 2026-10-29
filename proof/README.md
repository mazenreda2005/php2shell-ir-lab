# Phase 2 — Proof of Exposure (Pre-Patch Verification)

> **Status in this repo:** methodology + placeholder only.
> This folder documents *how* exposure is confirmed. It intentionally contains
> **no exploit code**. The actual confirmation is done with the version-based
> detector in [`../detection/`](../detection) and, optionally, a **published
> third-party scanner** that the operator runs manually.

---

## Goal

Before any remediation, establish and record a defensible answer to one question:

> *Is this node actually affected by php2shell (CVE-2026-109618 / CVE-2026-109619)?*

This is the same first move the official guidance calls for. The FBI/CISA
advisory (21 Oct 2026) told organisations to **inventory where PHP runs,
prioritise internet-facing systems, and apply version-specific updates** — not
to exploit their own hosts. So "proof" here means *authoritative version
confirmation*, not remote code execution.

## How exposure is confirmed (two independent signals)

**1. Version-based detection (primary, in this repo).**
Each node exposes its running PHP version (`/` and `/health.php`, see the demo
app). The detector in `../detection/` reads that version and compares it against
the official affected ranges. A node is **affected** if its PHP version is below
the patched baseline for its branch:

| Branch | Patched baseline | Affected if below |
|--------|------------------|-------------------|
| 8.5.x  | 8.5.12           | < 8.5.12          |
| 8.4.x  | 8.4.27           | < 8.4.27          |
| 8.3.x  | 8.3.36           | < 8.3.36          |
| 8.2.x  | **8.2.35**       | < 8.2.35          |

`web-01` boots on **8.2.20** → below 8.2.35 → **affected**. That is the
pre-patch proof, captured as a screenshot of the node banner and the detector
output.

**2. Published third-party scanner (optional, operator-run).**
For a second, independent signal, the operator may run a **publicly released
php2shell scanner** against the node and record its `vulnerable / not vulnerable`
verdict. Reputable sources that published detection tooling and technical
write-ups during this event include **watchTowr**, **Recorded Future**, and
major vendors (Sophos, Fortinet, Wiz). These report a verdict without weaponised
RCE.

> ⚠️ **Operator safety note.** During a live, high-profile event like this,
> GitHub fills with `poc.py` files of unknown provenance. Running an untrusted
> "exploit" against your own EC2 can backdoor the instance or your AWS account.
> Prefer a named vendor's scanner, read what it does first, and run it from an
> isolated host.

---

## 📌 Placeholder — where the manual proof artefact goes

*This is the spot reserved in the original plan for the proof step.*

The operator drops the evidence of pre-patch exposure here, e.g.:

```
proof/
├── README.md                ← you are here
├── web-01_version_before.png   (screenshot: node banner showing PHP 8.2.20)
├── scanner_output_before.txt   (optional: published scanner verdict = vulnerable)
└── web-01_version_after.png    (post-patch: banner showing PHP 8.2.35)
```

Nothing executable lives in this folder. The verdict logic is in
`../detection/`, and the post-patch re-check (Phase 5) reuses the exact same
detector to show the node is **no longer** affected — that symmetry is the
clean, reproducible proof the report is built on.
