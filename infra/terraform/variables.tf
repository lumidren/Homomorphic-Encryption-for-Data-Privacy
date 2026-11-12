variable "environment" {
  description = "Deployment environment name (staging or prod)."
  type        = string
  validation {
    condition     = contains(["staging", "prod"], var.environment)
    error_message = "environment must be staging or prod."
  }
}

variable "region" {
  description = "AWS region."
  type        = string
  default     = "us-east-1"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC."
  type        = string
  default     = "10.0.0.0/16"
}

variable "azs" {
  description = "Availability zones (three for production)."
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b", "us-east-1c"]
}

variable "kubernetes_version" {
  description = "EKS control plane version."
  type        = string
  default     = "1.32"
}

variable "api_node_instance_types" {
  description = "Instance types for the general node group (API, dashboard, ingress)."
  type        = list(string)
  default     = ["m7i.large"]
}

variable "worker_node_instance_types" {
  description = "Instance types for the FHE worker node group (memory-heavy: key bundles are large)."
  type        = list(string)
  default     = ["r7i.xlarge"]
}

variable "db_instance_class" {
  description = "RDS instance class."
  type        = string
  default     = "db.r7g.large"
}

variable "db_allocated_storage_gb" {
  description = "Initial RDS storage (autoscaling up to 5x)."
  type        = number
  default     = 100
}

variable "redis_node_type" {
  description = "ElastiCache node type."
  type        = string
  default     = "cache.r7g.large"
}

variable "api_domain" {
  description = "Public hostname of the API (e.g. api.ciphercompute.example.com)."
  type        = string
}

variable "dashboard_domain" {
  description = "Public hostname of the dashboard."
  type        = string
}

variable "acm_certificate_arn" {
  description = "ACM certificate covering api_domain and dashboard_domain."
  type        = string
}

variable "alarm_email" {
  description = "Address subscribed to the alarm SNS topic."
  type        = string
}

variable "backup_retention_days" {
  description = "Retention for AWS Backup recovery points and RDS automated backups."
  type        = number
  default     = 35
}

variable "waf_rate_limit_per_5min" {
  description = "Per-IP request ceiling enforced by WAF over five minutes."
  type        = number
  default     = 6000
}
