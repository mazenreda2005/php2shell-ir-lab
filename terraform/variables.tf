variable "project_name" {
  description = "Prefix used for naming and tagging all resources."
  type        = string
  default     = "php2shell-lab"
}

variable "instance_type" {
  description = "EC2 instance size. t3.micro is enough for the lab and stays cheap."
  type        = string
  default     = "t3.micro"
}

variable "php_patched_version" {
  description = "The known-good PHP version. Anything older is treated as vulnerable by the detection layer and the patch script upgrades to this."
  type        = string
  default     = "8.2.35"
}

variable "fleet" {
  description = <<-EOT
    The fleet to build. Each node runs its PHP version as a pinned Docker image
    (php:<version>-apache). One node is deliberately vulnerable; the rest are healthy.
    The PHPVersion/Status tags on each instance are the signal the detection Lambda watches.
  EOT
  type = map(object({
    php_version = string
    status      = string # "vulnerable" or "healthy"
  }))
  default = {
    "web-01" = { php_version = "8.2.20", status = "vulnerable" }
    "web-02" = { php_version = "8.2.35", status = "healthy" }
    "web-03" = { php_version = "8.2.35", status = "healthy" }
  }
}

variable "allowed_cidr" {
  description = <<-EOT
    CIDR allowed to reach SSH (22) and HTTP (80).
    Leave empty ("") to auto-detect the public IP of the machine running Terraform
    and lock access to that single address (/32). This keeps the vulnerable host
    OFF the open internet.
  EOT
  type    = string
  default = ""
}

variable "key_name" {
  description = "Name for the generated EC2 key pair."
  type        = string
  default     = "php2shell-lab-key"
}

# --- Automated incident response (Phase 4) ---

variable "enable_automation" {
  description = "Build the EventBridge + Lambda + SNS auto-response pipeline."
  type        = bool
  default     = true
}

variable "alert_email" {
  description = <<-EOT
    Email address to receive incident notifications via SNS.
    You must click the confirmation link AWS emails you after the first apply.
    Leave empty to create the topic without a subscription.
  EOT
  type    = string
  default = ""
}

variable "auto_contain" {
  description = "If true, the Lambda isolates an AFFECTED node automatically. If false, it only alerts."
  type        = bool
  default     = true
}

variable "detector_schedule" {
  description = "How often EventBridge runs the detector."
  type        = string
  default     = "rate(5 minutes)"
}

# --- Edge WAF (ALB + AWS WAF) ---
variable "enable_waf" {
  description = <<-EOT
    Build an Application Load Balancer in front of the fleet with an AWS WAF
    WebACL (Stage-A mitigation at the edge). NOTE: an ALB + WAF are NOT free —
    budget ~1 USD/day. Set false (and apply) to tear just this down.
  EOT
  type    = bool
  default = true
}
