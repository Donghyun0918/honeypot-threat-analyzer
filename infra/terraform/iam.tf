data "aws_caller_identity" "current" {}

locals {
  ssm_param_arn = "arn:aws:ssm:${var.region}:${data.aws_caller_identity.current.account_id}:parameter${var.ssm_prefix}/*"

  # s3://bucket/path → bucket, path
  models_bucket = var.models_s3_uri == "" ? "" : split("/", trimprefix(var.models_s3_uri, "s3://"))[0]
}

data "aws_iam_policy_document" "assume_ec2" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "app" {
  name               = "${var.project}-app"
  assume_role_policy = data.aws_iam_policy_document.assume_ec2.json
}

# Session Manager 접속 — SSH 를 열지 않아도 셸을 얻는다.
resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.app.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

data "aws_iam_policy_document" "app" {
  # SecureString 은 기본 키(aws/ssm)로 암호화한다. 그 키 정책이 계정 안에서 SSM 을 거친
  # 복호화를 이미 허용하므로 kms 권한은 따로 주지 않는다.
  statement {
    sid       = "ReadWriteOwnSecrets"
    actions   = ["ssm:GetParameter", "ssm:PutParameter"]
    resources = [local.ssm_param_arn]
  }

  dynamic "statement" {
    for_each = local.models_bucket == "" ? [] : [1]
    content {
      sid       = "ReadModels"
      actions   = ["s3:GetObject", "s3:ListBucket"]
      resources = ["arn:aws:s3:::${local.models_bucket}", "arn:aws:s3:::${local.models_bucket}/*"]
    }
  }
}

resource "aws_iam_role_policy" "app" {
  name   = "${var.project}-app"
  role   = aws_iam_role.app.id
  policy = data.aws_iam_policy_document.app.json
}

resource "aws_iam_instance_profile" "app" {
  name = "${var.project}-app"
  role = aws_iam_role.app.name
}
