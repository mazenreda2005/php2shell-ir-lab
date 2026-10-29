output "fleet" {
  description = "Each node's address, PHP version and status."
  value = {
    for k, inst in aws_instance.web : k => {
      instance_id = inst.id
      public_ip   = inst.public_ip
      url         = "http://${inst.public_ip}/"
      php_version = inst.tags["PHPVersion"]
      status      = inst.tags["Status"]
    }
  }
}

output "ssh_private_key_path" {
  description = "Path to the generated private key (chmod 0400)."
  value       = local_sensitive_file.private_key.filename
}

output "ssh_commands" {
  description = "Ready-to-use SSH command per node."
  value = {
    for k, inst in aws_instance.web : k =>
    "ssh -i ${local_sensitive_file.private_key.filename} ubuntu@${inst.public_ip}"
  }
}

output "operator_cidr" {
  description = "The CIDR that was granted access."
  value       = local.operator_cidr
}

output "security_group_id" {
  description = "Normal-operation security group."
  value       = aws_security_group.lab.id
}

output "quarantine_security_group_id" {
  description = "Isolation security group used by the isolate action / detection Lambda."
  value       = aws_security_group.quarantine.id
}

# --- Edge WAF (ALB + AWS WAF) ---
output "waf" {
  description = "Edge mitigation: the ALB entry point and WAF (null when disabled)."
  value = var.enable_waf ? {
    alb_url     = "http://${aws_lb.fleet[0].dns_name}/"
    web_acl     = aws_wafv2_web_acl.fleet[0].name
    rules       = "block-php2shell-upload-progress, aws-common, aws-known-bad-inputs, rate-limit"
    note        = "Send user traffic through alb_url; the WAF inspects it before PHP."
  } : null
}

# --- Automation (Phase 4) ---
output "automation" {
  description = "Automated incident-response resources (null when disabled)."
  value = var.enable_automation ? {
    lambda_function = aws_lambda_function.responder[0].function_name
    sns_topic       = aws_sns_topic.alerts[0].arn
    evidence_bucket = aws_s3_bucket.evidence[0].bucket
    schedule        = var.detector_schedule
    auto_contain    = var.auto_contain
    alert_email     = var.alert_email != "" ? var.alert_email : "(none — set -var alert_email=...)"
  } : null
}
