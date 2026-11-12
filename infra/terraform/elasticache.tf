resource "aws_security_group" "redis" {
  name        = "${local.name}-redis"
  description = "Redis: reachable from EKS nodes only"
  vpc_id      = module.vpc.vpc_id

  ingress {
    description     = "Redis from EKS nodes"
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [module.eks.node_security_group_id]
  }
}

resource "aws_elasticache_subnet_group" "main" {
  name       = local.name
  subnet_ids = module.vpc.private_subnets
}

# Note: this token is stored in Terraform state. The state backend is an S3 bucket encrypted with
# KMS, versioned, locked via DynamoDB and readable only by the deploy role (backend.hcl.example).
# Copy it into the application secret (CC_REDIS_URL) as described in RUNBOOK "Bootstrap secrets".
resource "random_password" "redis_auth" {
  length  = 48
  special = false
}

resource "aws_elasticache_replication_group" "main" {
  replication_group_id = local.name
  description          = "CipherCompute broker, rate limits and tenant semaphores"
  engine               = "redis"
  engine_version       = "7.1"
  node_type            = var.redis_node_type
  port                 = 6379

  num_cache_clusters         = var.environment == "prod" ? 2 : 1
  automatic_failover_enabled = var.environment == "prod"
  multi_az_enabled           = var.environment == "prod"

  subnet_group_name  = aws_elasticache_subnet_group.main.name
  security_group_ids = [aws_security_group.redis.id]

  at_rest_encryption_enabled = true
  kms_key_id                 = aws_kms_key.main.arn
  transit_encryption_enabled = true
  auth_token                 = random_password.redis_auth.result

  snapshot_retention_limit = 7
  snapshot_window          = "02:00-03:00"
  maintenance_window       = "sun:05:30-sun:06:30"
  apply_immediately        = false
}
