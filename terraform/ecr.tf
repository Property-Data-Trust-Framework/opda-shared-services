resource "aws_ecr_repository" "shared" {
  name                 = "opda-shared-services"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Project     = "opda-shared-services"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

resource "aws_ecr_lifecycle_policy" "shared" {
  repository = aws_ecr_repository.shared.name

  # Two rules — one per image — so each retains 10 versions independently.
  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep last 10 authorizer images"
        selection = {
          tagStatus     = "tagged"
          tagPrefixList = ["authorizer-"]
          countType     = "imageCountMoreThan"
          countNumber   = 10
        }
        action = { type = "expire" }
      },
      {
        rulePriority = 2
        description  = "Keep last 10 mtls images"
        selection = {
          tagStatus     = "tagged"
          tagPrefixList = ["mtls-"]
          countType     = "imageCountMoreThan"
          countNumber   = 10
        }
        action = { type = "expire" }
      },
    ]
  })
}

output "ecr_repository_url" {
  value       = aws_ecr_repository.shared.repository_url
  description = "Set this as SHARED_SERVICES_ECR_BASE in consumer repos"
}
