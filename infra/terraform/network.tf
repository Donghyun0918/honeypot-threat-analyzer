data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "main" {
  # checkov:skip=CKV2_AWS_11:단기 평가용 단일 서버. 트래픽 기록은 앱이 ES 에 남기고, flow log 는 비용 대비 쓸모가 적다
  cidr_block           = "10.40.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "${var.project}-vpc" }
}

# 기본 보안 그룹은 쓰지 않는다 — 규칙을 비워 두어 실수로 붙여도 아무것도 통하지 않게 한다.
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${var.project}-igw" }
}

resource "aws_subnet" "public" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.40.1.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]

  tags = { Name = "${var.project}-public" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = { Name = "${var.project}-public" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

resource "aws_security_group" "app" {
  name        = "${var.project}-app"
  description = "Dashboard, honeypots, admin ingress; all egress"
  vpc_id      = aws_vpc.main.id

  tags = { Name = "${var.project}-app" }
}

locals {
  # 허니팟 포트는 T-Pot 권장대로 1-64000 을 연다. 그 안의 8002(대시보드)만 빼서 dashboard_cidrs 로 따로 연다.
  honeypot_ranges = var.honeypot ? {
    "tcp-low"  = { protocol = "tcp", from = 1, to = 8001 }
    "tcp-high" = { protocol = "tcp", from = 8003, to = 64000 }
    "udp"      = { protocol = "udp", from = 1, to = 64000 }
  } : {}

  # T-Pot 설치 후 SSH 는 64295 로 옮겨진다(22 는 Cowrie 허니팟이 받는다).
  admin_ports = var.honeypot ? { ssh = 64295, tpot-web = 64297 } : { ssh = 22 }
  admin_rules = {
    for pair in setproduct(keys(local.admin_ports), var.admin_cidrs) :
    "${pair[0]}-${pair[1]}" => { port = local.admin_ports[pair[0]], cidr = pair[1] }
  }
}

resource "aws_vpc_security_group_ingress_rule" "honeypot" {
  # checkov:skip=CKV_AWS_24:허니팟 — 22 는 Cowrie 가 받는다. 관리 SSH 는 64295 이고 admin_cidrs 로만 연다
  # checkov:skip=CKV_AWS_25:허니팟 — 3389 등 전 포트 공개가 목적이다
  # checkov:skip=CKV_AWS_260:허니팟 — 80 은 웹 허니팟(snare/tanner)이 받는다
  for_each = local.honeypot_ranges

  security_group_id = aws_security_group.app.id
  description       = "T-Pot honeypots ${each.key}"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = each.value.protocol
  from_port         = each.value.from
  to_port           = each.value.to
}

# ES·Postgres·백엔드는 compose 에서 127.0.0.1 에만 묶여 있다. T-Pot ES(64298)도 마찬가지다.
resource "aws_vpc_security_group_ingress_rule" "dashboard" {
  for_each = toset(var.dashboard_cidrs)

  security_group_id = aws_security_group.app.id
  description       = "Next.js dashboard"
  cidr_ipv4         = each.value
  ip_protocol       = "tcp"
  from_port         = 8002
  to_port           = 8002
}

resource "aws_vpc_security_group_ingress_rule" "admin" {
  for_each = local.admin_rules

  security_group_id = aws_security_group.app.id
  description       = "Admin ${each.key}"
  cidr_ipv4         = each.value.cidr
  ip_protocol       = "tcp"
  from_port         = each.value.port
  to_port           = each.value.port
}

# 이미지 빌드(apt·pip·npm·gradle), 저장소 clone, Claude API, SSM 이 전부 바깥으로 나간다.
resource "aws_vpc_security_group_egress_rule" "all" {
  security_group_id = aws_security_group.app.id
  description       = "Outbound for builds, Claude API, SSM"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}
