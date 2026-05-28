data "aws_caller_identity" "current" {}

# The OIDC provider is created once by opda-ops. Its ARN is predictable so we
# construct it directly rather than looking it up (avoids needing iam:List*).
locals {
  github_oidc_provider_arn = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/token.actions.githubusercontent.com"
}

resource "aws_iam_role" "github_actions" {
  name = "opda-shared-services-github-actions"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = "sts:AssumeRoleWithWebIdentity"
      Principal = {
        Federated = local.github_oidc_provider_arn
      }
      Condition = {
        StringLike = {
          "token.actions.githubusercontent.com:sub" = [
            "repo:${var.github_repo}:ref:refs/heads/main",
            "repo:${var.github_repo}:environment:dev",
          ]
        }
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
        }
      }
    }]
  })

  tags = {
    Project   = "opda-shared-services"
    ManagedBy = "terraform"
  }
}

resource "aws_iam_role_policy" "github_actions" {
  name = "publish"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # ── ECR ────────────────────────────────────────────────────────────────
      {
        Sid      = "ECRAuthToken"
        Effect   = "Allow"
        Action   = ["ecr:GetAuthorizationToken"]
        Resource = "*"
      },
      {
        Sid    = "ECRSharedRepo"
        Effect = "Allow"
        Action = [
          "ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage",
          "ecr:CompleteLayerUpload", "ecr:CreateRepository",
          "ecr:DeleteLifecyclePolicy", "ecr:DescribeRepositories",
          "ecr:GetDownloadUrlForLayer", "ecr:GetLifecyclePolicy",
          "ecr:GetRepositoryPolicy", "ecr:InitiateLayerUpload",
          "ecr:ListTagsForResource", "ecr:PutImage",
          "ecr:PutLifecyclePolicy", "ecr:SetRepositoryPolicy",
          "ecr:UploadLayerPart",
        ]
        Resource = aws_ecr_repository.shared.arn
      },
      # ── Terraform state ────────────────────────────────────────────────────
      {
        Sid      = "TerraformStateBucket"
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = "arn:aws:s3:::ops-terraform-state-${data.aws_caller_identity.current.account_id}"
      },
      {
        Sid    = "TerraformStateObjects"
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
        Resource = "arn:aws:s3:::ops-terraform-state-${data.aws_caller_identity.current.account_id}/opda-shared-services/*"
      },
      # ── IAM self-management ────────────────────────────────────────────────
      # The pipeline manages its own role (trust policy, inline policy, tags).
      # Scoped to only this role's ARN.
      {
        Sid    = "IAMSelfManagement"
        Effect = "Allow"
        Action = [
          "iam:GetRole",
          "iam:GetRolePolicy",
          "iam:ListRolePolicies",
          "iam:ListAttachedRolePolicies",
          "iam:ListInstanceProfilesForRole",
          "iam:PutRolePolicy",
          "iam:DeleteRolePolicy",
          "iam:UpdateRole",
          "iam:UpdateAssumeRolePolicy",
          "iam:TagRole",
          "iam:UntagRole",
        ]
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/opda-shared-services-github-actions"
      },
    ]
  })
}

output "github_actions_role_arn" {
  value       = aws_iam_role.github_actions.arn
  description = "Set this as AWS_ROLE_ARN in the opda-shared-services GitHub Actions environment"
}
