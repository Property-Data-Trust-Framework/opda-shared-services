variable "environment" {
  type        = string
  description = "Deployment environment name (e.g. dev, staging, prod)"
}

variable "aws_region" {
  type    = string
  default = "eu-west-2"
}

variable "github_repo" {
  type        = string
  description = "GitHub repository in owner/repo format — used to scope the OIDC trust"
}
