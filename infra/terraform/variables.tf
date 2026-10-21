variable "project" {
  description = "리소스 이름 앞에 붙는 접두어"
  type        = string
  default     = "jsp-honeypot"
}

variable "region" {
  description = "배포 리전"
  type        = string
  default     = "ap-northeast-2"
}

variable "honeypot" {
  description = <<-EOT
    true 면 T-Pot(HIVE)을 설치해 실제 공격을 받고, 대시보드 스택은 T-Pot ES 를 읽는다.
    false 면 대시보드 스택만 띄운다(스택 안의 ES, 공격 수집 없음).
  EOT
  type        = bool
  default     = true
}

variable "instance_type" {
  description = <<-EOT
    T-Pot HIVE 는 RAM 16GB 를 요구한다(ES 4g · Kibana 2g · Logstash 1g + 허니팟 20여 개 + Suricata).
    여기에 대시보드 스택(약 3GB)이 더 얹힌다. Suricata 가 CPU 를 계속 써서 t3 는 크레딧이 바닥난다.
    honeypot = false 면 t3.large 로 충분하다.
  EOT
  type        = string
  default     = "m6i.xlarge"
}

variable "root_volume_gb" {
  description = "T-Pot 권장은 128GB 이상. 허니팟 로그 · ES 인덱스 · 이미지가 모두 루트 볼륨에 쌓인다."
  type        = number
  default     = 128
}

variable "dashboard_cidrs" {
  description = "대시보드(:8002)에 접속할 수 있는 대역. 허니팟 포트 범위에서 8002 만 빼서 따로 연다."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "admin_cidrs" {
  description = <<-EOT
    관리 포트 허용 대역. honeypot = true 면 SSH 64295 · T-Pot 웹(Kibana·어택맵) 64297,
    false 면 SSH 22. 비우면 관리 포트를 열지 않고 SSM Session Manager(포트 포워딩)로만 들어간다.
  EOT
  type        = list(string)
  default     = []
}

variable "key_name" {
  description = "SSH 를 쓸 때의 EC2 키 페어 이름. admin_cidrs 가 비어 있으면 없어도 된다."
  type        = string
  default     = null
}

variable "repo_url" {
  description = "서버에서 받을 저장소. 루트에 setup.sh · docker-compose.yml 이 있어야 한다."
  type        = string
  default     = "https://github.com/Donghyun0918/honeypot-threat-analyzer.git"
}

variable "repo_ref" {
  description = "체크아웃할 브랜치·태그·커밋"
  type        = string
  default     = "main"
}

variable "ssm_prefix" {
  description = <<-EOT
    비밀값을 읽어 올 SSM Parameter Store 경로. Terraform 은 값을 만들지 않는다(state 에 남지 않게).
    배포 전에 직접 넣는다:
      aws ssm put-parameter --type SecureString --name <prefix>/anthropic_api_key --value ...
    <prefix>/postgres_password 는 없으면 서버가 처음 기동할 때 만들어 저장한다.
  EOT
  type        = string
  default     = "/jsp-honeypot"
}

variable "llm_model" {
  description = "평가 배포의 해설 모델(LLM_PROVIDER=anthropic)"
  type        = string
  default     = "claude-haiku-5-5"
}

variable "models_s3_uri" {
  description = "학습된 분류 모델(multi_model.pkl 등)이 있는 S3 경로. 저장소에 모델이 없으므로 비우면 규칙만으로 분류한다."
  type        = string
  default     = ""
}

variable "seed_demo_data" {
  description = "setup.sh 의 시연 데이터 주입. 평가 수치에 시험 이벤트가 섞이므로 기본은 끈다."
  type        = bool
  default     = false
}

variable "tpot_version" {
  description = "설치할 T-Pot 버전(telekom-security/tpotce 의 태그·브랜치). 저장소의 tpotce/ 와 같은 판으로 맞춘다."
  type        = string
  default     = "24.04.1"
}

variable "tpot_web_user" {
  description = "T-Pot 웹(64297) 로그인 이름. 비밀번호는 서버가 만들어 SSM <ssm_prefix>/tpot_web_password 에 저장한다."
  type        = string
  default     = "tpotadmin"
}

variable "expire_hours" {
  description = "0 보다 크면 서버가 첫 부팅 이 시간 뒤 스스로 꺼지고 종료(terminate)된다 — 루트 볼륨도 지워진다. 남는 VPC · EIP 는 terraform destroy 로 지운다."
  type        = number
  default     = 0
}
