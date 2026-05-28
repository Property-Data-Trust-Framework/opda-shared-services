# `bucket`, `region`, and `key` are all supplied at init time so the account ID
# is not committed. The publish workflow resolves `bucket` from AWS automatically.
#
# Local init:
#   BUCKET="ops-terraform-state-$(aws sts get-caller-identity --query Account --output text)"
#   terraform init \
#     -backend-config="bucket=$BUCKET" \
#     -backend-config="region=eu-west-2" \
#     -backend-config="key=opda-shared-services/terraform.tfstate"

terraform {
  backend "s3" {
    use_lockfile = true
  }
}
