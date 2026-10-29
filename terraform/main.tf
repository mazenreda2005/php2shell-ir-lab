# ---------------------------------------------------------------------------
# php2shell Incident-Response Lab — core infrastructure
# A 3-node EC2 fleet. One node runs a KNOWN-VULNERABLE PHP version
# (CVE-2026-109618 / CVE-2026-109619, "php2shell"); the others are patched.
# Each node runs PHP as a pinned Docker image (php:<ver>-apache = Apache + mod_php,
# the most exposed config in the advisory). Access is locked to the operator's
# own IP so the vulnerable box is never exposed to the open internet.
# ---------------------------------------------------------------------------

# --- Auto-detect the operator's public IP (used when allowed_cidr is empty) ---
data "http" "my_ip" {
  count = var.allowed_cidr == "" ? 1 : 0
  url   = "https://checkip.amazonaws.com/"
}

locals {
  operator_cidr = var.allowed_cidr != "" ? var.allowed_cidr : "${chomp(data.http.my_ip[0].response_body)}/32"
}

# --- Latest Ubuntu 22.04 LTS AMI from Canonical ---
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

data "aws_vpc" "default" {
  default = true
}

# --- SSH key pair: generated locally, saved as a .pem you keep ---
resource "tls_private_key" "lab" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "lab" {
  key_name   = var.key_name
  public_key = tls_private_key.lab.public_key_openssh
}

resource "local_sensitive_file" "private_key" {
  content         = tls_private_key.lab.private_key_pem
  filename        = "${path.module}/${var.key_name}.pem"
  file_permission = "0400"
}

# --- Security group: normal operating state (SSH + HTTP, operator IP only) ---
resource "aws_security_group" "lab" {
  name        = "${var.project_name}-sg"
  description = "Operator-only access to the IR lab fleet"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "SSH from operator"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [local.operator_cidr]
  }

  ingress {
    description = "HTTP from operator (demo web app)"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [local.operator_cidr]
  }

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name  = "${var.project_name}-sg"
    Fleet = var.project_name
  }
}

# --- Quarantine security group: no ingress at all. ---
# The "isolate" action and the detection Lambda move a node onto this SG,
# cutting it off from the network while keeping the instance alive for forensics.
resource "aws_security_group" "quarantine" {
  name        = "${var.project_name}-quarantine-sg"
  description = "Isolated node: no inbound, no outbound"
  vpc_id      = data.aws_vpc.default.id

  tags = {
    Name  = "${var.project_name}-quarantine-sg"
    Fleet = var.project_name
  }
}

# --- The fleet ---
resource "aws_instance" "web" {
  for_each = var.fleet

  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  key_name               = aws_key_pair.lab.key_name
  vpc_security_group_ids = [aws_security_group.lab.id]

  user_data = templatefile("${path.module}/user_data.sh.tftpl", {
    php_version = each.value.php_version
  })

  # These tags ARE the signal the detection Lambda watches.
  # When you patch a node, its PHPVersion tag flips to the patched value.
  tags = {
    Name       = "${var.project_name}-${each.key}"
    Role       = "web"
    Fleet      = var.project_name
    PHPVersion = each.value.php_version
    Status     = each.value.status
  }

  root_block_device {
    volume_size = 10
    volume_type = "gp3"
  }

  # PHPVersion/Status are operational state: they change at runtime when the
  # responder isolates a node or an operator patches it. Terraform sets the
  # initial values at create time but must NOT revert later drift, or it would
  # undo a remediation (and make the detector re-isolate a patched node).
  lifecycle {
    ignore_changes = [tags["PHPVersion"], tags["Status"]]
  }
}
