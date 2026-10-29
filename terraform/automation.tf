# ---------------------------------------------------------------------------
# Phase 4 — Automated Incident Response
# EventBridge (schedule) -> Lambda (detect + contain) -> SNS (alert)
#                        -> CloudWatch Logs  +  S3 (encrypted evidence)
# All resources are gated behind var.enable_automation.
# ---------------------------------------------------------------------------

locals {
  auto = var.enable_automation ? 1 : 0
}

data "aws_caller_identity" "current" {}

# --- SNS topic + optional email subscription ---
resource "aws_sns_topic" "alerts" {
  count = local.auto
  name  = "${var.project_name}-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  count     = (var.enable_automation && var.alert_email != "") ? 1 : 0
  topic_arn = aws_sns_topic.alerts[0].arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# --- S3 bucket for encrypted evidence ---
resource "aws_s3_bucket" "evidence" {
  count         = local.auto
  bucket        = "${var.project_name}-evidence-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  count                   = local.auto
  bucket                  = aws_s3_bucket.evidence[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  count  = local.auto
  bucket = aws_s3_bucket.evidence[0].id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

resource "aws_s3_bucket_versioning" "evidence" {
  count  = local.auto
  bucket = aws_s3_bucket.evidence[0].id
  versioning_configuration { status = "Enabled" }
}

# --- Package the Lambda source ---
data "archive_file" "lambda" {
  count       = local.auto
  type        = "zip"
  source_file = "${path.module}/../lambda/detector_responder.py"
  output_path = "${path.module}/.build/detector_responder.zip"
}

# --- Least-privilege IAM role for the Lambda ---
data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda" {
  count              = local.auto
  name               = "${var.project_name}-responder-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

data "aws_iam_policy_document" "lambda_perms" {
  # Describe actions cannot be resource-scoped.
  statement {
    sid       = "Describe"
    actions   = ["ec2:DescribeInstances", "ec2:DescribeSecurityGroups"]
    resources = ["*"]
  }
  # Write actions limited to instances tagged for this fleet.
  statement {
    sid     = "ContainFleetOnly"
    actions = ["ec2:ModifyInstanceAttribute", "ec2:CreateTags"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "ec2:ResourceTag/Fleet"
      values   = [var.project_name]
    }
  }
  statement {
    sid       = "Notify"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts[0].arn]
  }
  statement {
    sid       = "Evidence"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.evidence[0].arn}/*"]
  }
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:aws:logs:*:*:*"]
  }
}

resource "aws_iam_role_policy" "lambda" {
  count  = local.auto
  name   = "${var.project_name}-responder-policy"
  role   = aws_iam_role.lambda[0].id
  policy = data.aws_iam_policy_document.lambda_perms.json
}

resource "aws_cloudwatch_log_group" "lambda" {
  count             = local.auto
  name              = "/aws/lambda/${var.project_name}-responder"
  retention_in_days = 14
}

# --- The responder Lambda ---
resource "aws_lambda_function" "responder" {
  count            = local.auto
  function_name    = "${var.project_name}-responder"
  role             = aws_iam_role.lambda[0].arn
  handler          = "detector_responder.handler"
  runtime          = "python3.12"
  timeout          = 60
  filename         = data.archive_file.lambda[0].output_path
  source_code_hash = data.archive_file.lambda[0].output_base64sha256

  environment {
    variables = {
      FLEET_NAME       = var.project_name
      QUARANTINE_SG_ID = aws_security_group.quarantine.id
      SNS_TOPIC_ARN    = aws_sns_topic.alerts[0].arn
      EVIDENCE_BUCKET  = aws_s3_bucket.evidence[0].bucket
      AUTO_CONTAIN     = tostring(var.auto_contain)
      BASELINES_JSON   = jsonencode({ "8.5" = [8, 5, 12], "8.4" = [8, 4, 27], "8.3" = [8, 3, 36], "8.2" = [8, 2, 35] })
    }
  }
  depends_on = [aws_cloudwatch_log_group.lambda]
}

# --- EventBridge schedule -> Lambda ---
resource "aws_cloudwatch_event_rule" "schedule" {
  count               = local.auto
  name                = "${var.project_name}-detector-schedule"
  description         = "Periodically run the php2shell detector/responder"
  schedule_expression = var.detector_schedule
}

resource "aws_cloudwatch_event_target" "lambda" {
  count     = local.auto
  rule      = aws_cloudwatch_event_rule.schedule[0].name
  target_id = "responder"
  arn       = aws_lambda_function.responder[0].arn
}

resource "aws_lambda_permission" "events" {
  count         = local.auto
  statement_id  = "AllowEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.responder[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.schedule[0].arn
}
