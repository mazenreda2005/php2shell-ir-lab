"""
detector_responder.py — automated php2shell incident response (AWS Lambda).

Triggered on a schedule by EventBridge. For every running node in the fleet it:
  1. Builds a STRUCTURED finding (instance id, observed version, source,
     timestamp, incident id) and classifies it:
        AFFECTED  — PHP below the official patched baseline for its branch
        PATCHED   — PHP at/above the baseline
        UNKNOWN   — version could not be determined
     Compromise is NEVER inferred from a vulnerable version alone; a
     'suspected_compromise' flag is only set if real IoC evidence is supplied
     (none is fabricated here).
  2. Confirms the instance belongs to the authorized fleet (tag Fleet == FLEET_NAME).
  3. De-duplicates: a node already isolated (Status tag == 'isolated' or already
     on the quarantine SG) is not re-actioned.
  4. If AUTO_CONTAIN is enabled and the node is AFFECTED and not yet contained:
       - records the finding as evidence to S3 (if a bucket is configured),
       - isolates the node by moving it onto the quarantine security group,
       - verifies the resulting security-group membership,
       - publishes an SNS notification with the REAL execution result.
     If AUTO_CONTAIN is disabled it only alerts (detect + notify), never isolates.
  5. Records failures and partial results. Nothing is reported as "done" before
     the result is confirmed by a follow-up describe call.

Environment variables:
  FLEET_NAME        fleet tag value (e.g. php2shell-lab)
  QUARANTINE_SG_ID  security group id used for isolation
  SNS_TOPIC_ARN     topic for notifications
  EVIDENCE_BUCKET   S3 bucket for evidence (optional)
  AUTO_CONTAIN      "true" | "false"  — whether to isolate automatically
  BASELINES_JSON    JSON of {branch: [maj,min,patch]} patched baselines
"""
import os, json, datetime, uuid
import boto3

ec2 = boto3.client("ec2")
sns = boto3.client("sns")
s3 = boto3.client("s3")

FLEET_NAME       = os.environ["FLEET_NAME"]
QUARANTINE_SG_ID = os.environ["QUARANTINE_SG_ID"]
SNS_TOPIC_ARN    = os.environ.get("SNS_TOPIC_ARN", "")
EVIDENCE_BUCKET  = os.environ.get("EVIDENCE_BUCKET", "")
AUTO_CONTAIN     = os.environ.get("AUTO_CONTAIN", "true").lower() == "true"
BASELINES        = json.loads(os.environ.get("BASELINES_JSON",
                     '{"8.5":[8,5,12],"8.4":[8,4,27],"8.3":[8,3,36],"8.2":[8,2,35]}'))


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def parse_ver(v):
    try:
        return tuple(int(x) for x in str(v).split(".")[:3])
    except Exception:
        return None

def classify(version):
    t = parse_ver(version)
    if not t:
        return "UNKNOWN"
    base = BASELINES.get(f"{t[0]}.{t[1]}")
    if not base:
        return "UNKNOWN"
    return "AFFECTED" if t < tuple(base) else "PATCHED"

def tags_of(inst):
    return {t["Key"]: t["Value"] for t in inst.get("Tags", [])}

def fleet_instances():
    paginator = ec2.get_paginator("describe_instances")
    out = []
    for page in paginator.paginate(Filters=[
        {"Name": "tag:Fleet", "Values": [FLEET_NAME]},
        {"Name": "instance-state-name", "Values": ["running"]},
    ]):
        for r in page["Reservations"]:
            out.extend(r["Instances"])
    return out

def current_sg_ids(inst):
    return [g["GroupId"] for g in inst.get("SecurityGroups", [])]

def isolate(instance_id):
    """Move the instance onto ONLY the quarantine SG, then verify."""
    ec2.modify_instance_attribute(InstanceId=instance_id, Groups=[QUARANTINE_SG_ID])
    ec2.create_tags(Resources=[instance_id], Tags=[{"Key": "Status", "Value": "isolated"}])
    # verify
    d = ec2.describe_instances(InstanceIds=[instance_id])
    inst = d["Reservations"][0]["Instances"][0]
    sgs = current_sg_ids(inst)
    return sgs == [QUARANTINE_SG_ID], sgs

def put_evidence(finding):
    if not EVIDENCE_BUCKET:
        return None
    key = f"findings/{finding['incident_id']}/{finding['instance_id']}.json"
    s3.put_object(
        Bucket=EVIDENCE_BUCKET, Key=key,
        Body=json.dumps(finding, indent=2).encode(),
        ContentType="application/json",
        ServerSideEncryption="AES256",
    )
    return f"s3://{EVIDENCE_BUCKET}/{key}"

def notify(subject, message):
    if SNS_TOPIC_ARN:
        sns.publish(TopicArn=SNS_TOPIC_ARN, Subject=subject[:100], Message=message)

def handler(event, context):
    incident_id = "INC-" + datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d") \
                  + "-" + uuid.uuid4().hex[:6]
    results, actioned, errors = [], [], []

    for inst in fleet_instances():
        iid = inst["InstanceId"]
        t = tags_of(inst)
        if t.get("Fleet") != FLEET_NAME:       # authorization guard
            continue
        version = t.get("PHPVersion", "")
        state = classify(version)
        already_isolated = t.get("Status") == "isolated" or current_sg_ids(inst) == [QUARANTINE_SG_ID]

        finding = {
            "incident_id": incident_id,
            "instance_id": iid,
            "name": t.get("Name", iid),
            "observed_version": version,
            "classification": state,          # AFFECTED | PATCHED | UNKNOWN
            "source": "instance-tag",
            "suspected_compromise": False,    # never inferred from version alone
            "timestamp": now_iso(),
            "already_isolated": already_isolated,
            "action": "none",
            "result": "observed",
        }

        try:
            if state == "AFFECTED" and not already_isolated:
                if AUTO_CONTAIN:
                    finding["evidence"] = put_evidence(finding)
                    ok, sgs = isolate(iid)
                    finding["action"] = "isolate"
                    finding["result"] = "isolated_verified" if ok else "isolation_unverified"
                    finding["post_sg"] = sgs
                    actioned.append(finding)
                    notify(
                        f"[{incident_id}] {finding['name']} isolated (php2shell)",
                        json.dumps(finding, indent=2),
                    )
                else:
                    finding["action"] = "alert_only"
                    finding["result"] = "detected_not_contained"
                    actioned.append(finding)
                    notify(
                        f"[{incident_id}] {finding['name']} AFFECTED — auto-contain OFF",
                        json.dumps(finding, indent=2),
                    )
        except Exception as e:
            finding["result"] = "error"
            finding["error"] = str(e)
            errors.append(finding)

        results.append(finding)
        print(json.dumps(finding))   # -> CloudWatch Logs

    summary = {
        "incident_id": incident_id,
        "scanned": len(results),
        "actioned": len(actioned),
        "errors": len(errors),
        "auto_contain": AUTO_CONTAIN,
    }
    print(json.dumps({"summary": summary}))
    return summary
