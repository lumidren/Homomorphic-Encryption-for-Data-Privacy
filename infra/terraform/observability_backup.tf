# ----- CloudWatch alarms ---------------------------------------------------------------------

resource "aws_sns_topic" "alarms" {
  name              = "${local.name}-alarms"
  kms_master_key_id = aws_kms_key.main.id
}

resource "aws_sns_topic_subscription" "alarms_email" {
  topic_arn = aws_sns_topic.alarms.arn
  protocol  = "email"
  endpoint  = var.alarm_email
}

locals {
  alarms = {
    alb-5xx = {
      namespace  = "AWS/ApplicationELB"
      metric     = "HTTPCode_Target_5XX_Count"
      stat       = "Sum"
      threshold  = 50
      comparison = "GreaterThanThreshold"
      dimensions = { LoadBalancer = aws_lb.main.arn_suffix }
    }
    alb-unhealthy-targets = {
      namespace  = "AWS/ApplicationELB"
      metric     = "UnHealthyHostCount"
      stat       = "Maximum"
      threshold  = 0
      comparison = "GreaterThanThreshold"
      dimensions = { LoadBalancer = aws_lb.main.arn_suffix, TargetGroup = aws_lb_target_group.ingress.arn_suffix }
    }
    rds-cpu = {
      namespace  = "AWS/RDS"
      metric     = "CPUUtilization"
      stat       = "Average"
      threshold  = 80
      comparison = "GreaterThanThreshold"
      dimensions = { DBInstanceIdentifier = aws_db_instance.main.identifier }
    }
    rds-free-storage = {
      namespace  = "AWS/RDS"
      metric     = "FreeStorageSpace"
      stat       = "Minimum"
      threshold  = 10 * 1024 * 1024 * 1024
      comparison = "LessThanThreshold"
      dimensions = { DBInstanceIdentifier = aws_db_instance.main.identifier }
    }
    redis-memory = {
      namespace  = "AWS/ElastiCache"
      metric     = "DatabaseMemoryUsagePercentage"
      stat       = "Maximum"
      threshold  = 80
      comparison = "GreaterThanThreshold"
      dimensions = { ReplicationGroupId = aws_elasticache_replication_group.main.id }
    }
    waf-blocked-spike = {
      namespace  = "AWS/WAFV2"
      metric     = "BlockedRequests"
      stat       = "Sum"
      threshold  = 1000
      comparison = "GreaterThanThreshold"
      dimensions = { WebACL = aws_wafv2_web_acl.main.name, Region = var.region, Rule = "ALL" }
    }
  }
}

resource "aws_cloudwatch_metric_alarm" "main" {
  for_each = local.alarms

  alarm_name          = "${local.name}-${each.key}"
  namespace           = each.value.namespace
  metric_name         = each.value.metric
  statistic           = each.value.stat
  threshold           = each.value.threshold
  comparison_operator = each.value.comparison
  dimensions          = each.value.dimensions
  period              = 300
  evaluation_periods  = 2
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alarms.arn]
  ok_actions          = [aws_sns_topic.alarms.arn]
}

# ----- AWS Backup: Postgres + object storage ---------------------------------------------------

resource "aws_backup_vault" "main" {
  name        = local.name
  kms_key_arn = aws_kms_key.main.arn
}

resource "aws_backup_plan" "main" {
  name = local.name

  rule {
    rule_name         = "daily"
    target_vault_name = aws_backup_vault.main.name
    schedule          = "cron(0 5 * * ? *)"
    start_window      = 60
    completion_window = 360
    lifecycle {
      delete_after = var.backup_retention_days
    }
  }

  rule {
    rule_name         = "continuous"
    target_vault_name = aws_backup_vault.main.name
    # Point-in-time recovery for RDS and S3 within the retention window.
    enable_continuous_backup = true
    lifecycle {
      delete_after = var.backup_retention_days
    }
  }
}

resource "aws_iam_role" "backup" {
  name = "${local.name}-backup"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "backup.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "backup" {
  for_each = toset([
    "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup",
    "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForRestores",
    "arn:aws:iam::aws:policy/AWSBackupServiceRolePolicyForS3Backup",
    "arn:aws:iam::aws:policy/AWSBackupServiceRolePolicyForS3Restore",
  ])
  role       = aws_iam_role.backup.name
  policy_arn = each.value
}

resource "aws_backup_selection" "main" {
  name         = local.name
  plan_id      = aws_backup_plan.main.id
  iam_role_arn = aws_iam_role.backup.arn
  resources    = [aws_db_instance.main.arn, aws_s3_bucket.data.arn]
}
