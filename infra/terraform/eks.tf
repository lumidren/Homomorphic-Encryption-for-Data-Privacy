module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.31"

  cluster_name    = local.name
  cluster_version = var.kubernetes_version

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  # Control plane reachable from the internet only for authenticated kubectl/CI; nodes are private.
  cluster_endpoint_public_access           = true
  cluster_endpoint_private_access          = true
  enable_irsa                              = true
  enable_cluster_creator_admin_permissions = true

  cluster_enabled_log_types              = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
  cloudwatch_log_group_retention_in_days = 90

  # Kubernetes Secrets (synced from Secrets Manager) are envelope-encrypted with our KMS key.
  cluster_encryption_config = {
    resources        = ["secrets"]
    provider_key_arn = aws_kms_key.main.arn
  }

  eks_managed_node_groups = {
    general = {
      instance_types = var.api_node_instance_types
      min_size       = var.environment == "prod" ? 3 : 2
      max_size       = 12
      desired_size   = var.environment == "prod" ? 3 : 2
      labels         = { "ciphercompute.dev/pool" = "general" }
    }
    fhe = {
      instance_types = var.worker_node_instance_types
      min_size       = var.environment == "prod" ? 2 : 1
      max_size       = 30
      desired_size   = var.environment == "prod" ? 2 : 1
      labels         = { "ciphercompute.dev/pool" = "fhe" }
      taints = {
        fhe = { key = "ciphercompute.dev/fhe", value = "true", effect = "NO_SCHEDULE" }
      }
    }
  }

  node_security_group_additional_rules = {
    ingress_alb = {
      description              = "ALB to ingress-nginx"
      protocol                 = "tcp"
      from_port                = 8443
      to_port                  = 8443
      type                     = "ingress"
      source_security_group_id = aws_security_group.alb.id
    }
  }
}
