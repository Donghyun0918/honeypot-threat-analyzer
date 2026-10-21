data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }
}

resource "aws_instance" "app" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.app.id]
  iam_instance_profile   = aws_iam_instance_profile.app.name
  key_name               = var.key_name
  ebs_optimized          = true
  monitoring             = true

  # 2층 구조: Terraform 은 인프라까지, 서비스 기동은 user_data 가 setup.sh 에 넘긴다.
  user_data = templatefile("${path.module}/user_data.sh.tftpl", {
    region         = var.region
    repo_url       = var.repo_url
    repo_ref       = var.repo_ref
    ssm_prefix     = var.ssm_prefix
    llm_model      = var.llm_model
    models_s3_uri  = var.models_s3_uri
    seed_demo_data = var.seed_demo_data
    honeypot       = var.honeypot
    tpot_version   = var.tpot_version
    tpot_web_user  = var.tpot_web_user
  })
  # user_data 를 고쳐도 서버를 갈아엎지 않는다(ES 데이터가 루트 볼륨에 있다).
  # 다시 부트스트랩하려면 terraform apply -replace=aws_instance.app
  user_data_replace_on_change = false

  metadata_options {
    http_tokens                 = "required" # IMDSv2 만
    http_put_response_hop_limit = 1          # 컨테이너에서 인스턴스 자격 증명에 닿지 못하게
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = var.root_volume_gb
    encrypted             = true
    delete_on_termination = true
  }

  lifecycle {
    ignore_changes = [ami] # 새 AMI 가 나와도 서버를 바꾸지 않는다
  }

  tags = { Name = "${var.project}-app" }
}

# 재부팅해도 주소가 바뀌지 않게(5월 운영 때 재부팅으로 IP 가 바뀌었다).
resource "aws_eip" "app" {
  domain   = "vpc"
  instance = aws_instance.app.id

  tags = { Name = "${var.project}-app" }

  depends_on = [aws_internet_gateway.main]
}
