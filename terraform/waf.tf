# ---------------------------------------------------------------------------
# Edge WAF — Application Load Balancer + AWS WAF (Stage-A mitigation)
# User traffic enters through an internet-facing ALB. An AWS WAF WebACL in
# front of it inspects every HTTP request and BLOCKS the php2shell attack
# pattern before it can reach PHP, plus AWS-managed rule groups and a
# per-IP rate limit. Gated behind var.enable_waf (ALB + WAF are not free).
# ---------------------------------------------------------------------------

locals {
  waf = var.enable_waf ? 1 : 0
}

# Default-VPC subnets (ALB needs at least two AZs).
data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

# --- ALB security group: operator-only on 80 ---
resource "aws_security_group" "alb" {
  count       = local.waf
  name        = "${var.project_name}-alb-sg"
  description = "Operator-only HTTP to the fleet ALB"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "HTTP from operator"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [local.operator_cidr]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "${var.project_name}-alb-sg", Fleet = var.project_name }
}

# Let the ALB reach the nodes on 80 (added to the normal node SG).
resource "aws_security_group_rule" "alb_to_nodes" {
  count                    = local.waf
  type                     = "ingress"
  from_port                = 80
  to_port                  = 80
  protocol                 = "tcp"
  security_group_id        = aws_security_group.lab.id
  source_security_group_id = aws_security_group.alb[0].id
  description              = "HTTP from the fleet ALB"
}

# --- Application Load Balancer ---
resource "aws_lb" "fleet" {
  count              = local.waf
  name               = "${var.project_name}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb[0].id]
  subnets            = slice(data.aws_subnets.default.ids, 0, 2)
  tags               = { Name = "${var.project_name}-alb" }
}

resource "aws_lb_target_group" "fleet" {
  count    = local.waf
  name     = "${var.project_name}-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = data.aws_vpc.default.id

  health_check {
    path                = "/health.php"
    matcher             = "200"
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
  tags = { Name = "${var.project_name}-tg" }
}

resource "aws_lb_target_group_attachment" "fleet" {
  for_each         = var.enable_waf ? aws_instance.web : {}
  target_group_arn = aws_lb_target_group.fleet[0].arn
  target_id        = each.value.id
  port             = 80
}

resource "aws_lb_listener" "http" {
  count             = local.waf
  load_balancer_arn = aws_lb.fleet[0].arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.fleet[0].arn
  }
}

# --- AWS WAF WebACL ---
resource "aws_wafv2_web_acl" "fleet" {
  count = local.waf
  name  = "${var.project_name}-waf"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  # Rule 1 — block the php2shell attack vector at the edge.
  # The exploit path reaches PHP via the session upload-progress feature;
  # requests carrying that trigger field are dropped before they hit mod_php.
  rule {
    name     = "block-php2shell-upload-progress"
    priority = 1
    action {
      block {}
    }
    statement {
      byte_match_statement {
        search_string         = "PHP_SESSION_UPLOAD_PROGRESS"
        positional_constraint = "CONTAINS"
        field_to_match {
          body {}
        }
        text_transformation {
          priority = 0
          type     = "NONE"
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "block-php2shell"
      sampled_requests_enabled   = true
    }
  }

  # Rule 2 — AWS managed Core Rule Set (OWASP-style common protections).
  rule {
    name     = "aws-common"
    priority = 2
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "aws-common"
      sampled_requests_enabled   = true
    }
  }

  # Rule 3 — AWS managed Known Bad Inputs.
  rule {
    name     = "aws-known-bad-inputs"
    priority = 3
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "aws-known-bad-inputs"
      sampled_requests_enabled   = true
    }
  }

  # Rule 4 — per-IP rate limit (blunt DoS / brute-force brake).
  rule {
    name     = "rate-limit"
    priority = 4
    action {
      block {}
    }
    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "rate-limit"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.project_name}-waf"
    sampled_requests_enabled   = true
  }

  tags = { Name = "${var.project_name}-waf" }
}

resource "aws_wafv2_web_acl_association" "alb" {
  count        = local.waf
  resource_arn = aws_lb.fleet[0].arn
  web_acl_arn  = aws_wafv2_web_acl.fleet[0].arn
}
