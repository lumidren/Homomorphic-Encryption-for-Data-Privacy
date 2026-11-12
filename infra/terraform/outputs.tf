output "cluster_name" {
  value = module.eks.cluster_name
}

output "alb_dns_name" {
  description = "Point api_domain and dashboard_domain (CNAME/alias) here."
  value       = aws_lb.main.dns_name
}

output "ingress_target_group_arn" {
  description = "Referenced by the TargetGroupBinding that registers ingress-nginx pods."
  value       = aws_lb_target_group.ingress.arn
}

output "data_bucket" {
  value = aws_s3_bucket.data.bucket
}

output "kms_key_arn" {
  value = aws_kms_key.main.arn
}

output "app_role_arn" {
  description = "IRSA role for the Helm release service account."
  value       = aws_iam_role.app.arn
}

output "db_endpoint" {
  value = aws_db_instance.main.address
}

output "db_master_secret_arn" {
  value = aws_db_instance.main.master_user_secret[0].secret_arn
}

output "redis_endpoint" {
  value = aws_elasticache_replication_group.main.primary_endpoint_address
}

output "app_secret_arn" {
  value = aws_secretsmanager_secret.app.arn
}
