# AWS 배포 (Terraform)

2층 구조: **Terraform 이 인프라**(VPC · 보안 그룹 · IAM · EC2 · Elastic IP)를 만들고,
**user_data 가 서비스**를 띄운다. `honeypot` 변수로 두 가지 배치를 고른다.

| | `honeypot = true` (기본) | `honeypot = false` |
|---|---|---|
| 내용 | T-Pot HIVE 로 **실제 공격 수집** + 대시보드 스택이 T-Pot ES 를 읽음 | 대시보드 스택만(스택 안의 ES) |
| 서버 | `m6i.xlarge`(16GB) · 128GB | `t3.large` 로 충분 |
| 부트스트랩 | T-Pot 설치 → **재부팅** → `jsp-stage2.service` 가 `setup.sh` | `setup.sh` 한 번 |
| 열리는 포트 | 허니팟 TCP/UDP 1-64000(전체 공개), 8002 는 `dashboard_cidrs` | 8002 |
| 관리 포트 | SSH 64295 · T-Pot 웹 64297 (`admin_cidrs` 에서만) | SSH 22 (`admin_cidrs` 에서만) |

`admin_cidrs` 를 비우면 관리 포트를 하나도 열지 않는다 — 셸은 SSM Session Manager, T-Pot 웹은
SSM 포트 포워딩(`terraform output tpot_web_tunnel`)으로 들어간다.

허니팟 배치의 T-Pot 은 원본 24.04.1 을 설치한 뒤 `tpotce/compose/aws_overlay.yml` 로 우리 수정분을 얹는다
(tpot.service drop-in 이 이 파일을 같이 쓴다): **threat-console**(`/threat-console/`), **한국어 Kibana** 저장 객체,
**한국어 메인 페이지**, **어택맵 OSM 타일 패치**. 분류기 · 해설기는 대시보드 스택 쪽에서 한 번만 돈다.

허니팟 배치에서 대시보드 스택은 `docker-compose.tpot.yml` 이 덧씌워진다(`.env` 의 `COMPOSE_FILE`).
스택 안의 ES · Ollama · 어택맵은 띄우지 않고, 백엔드 · 분류기 · 해설기 · 프론트만 T-Pot 의
`tpotce_nginx_local` 네트워크에 붙어 T-Pot ES 를 읽는다. 허니팟 컨테이너들은 이 네트워크에 없다.

## 배포

```bash
# 1) Claude 키를 SSM 에 넣는다 — Terraform state 와 user_data 에는 남지 않는다
aws ssm put-parameter --region ap-northeast-2 --type SecureString \
  --name /jsp-honeypot/anthropic_api_key --value 'sk-ant-...'
#    postgres_password · tpot_web_password 는 서버가 첫 부팅 때 만들어 같은 경로에 저장한다

# 2) 인프라
cp terraform.tfvars.example terraform.tfvars   # 필요하면 고친다
terraform init
terraform apply

# 3) 진행 확인 — 허니팟 배치는 T-Pot 설치 · 재부팅 · 이미지 빌드까지 30~40분
$(terraform output -raw ssm_session)
sudo tail -f /var/log/jsp-bootstrap.log     # 마지막 줄 "bootstrap 끝"
```

끝나면 `terraform output dashboard_url` 로 접속해 계정을 만든다(시연 계정은 `seed_demo_data` 를 켤 때만 생긴다).

## 알아둘 것

- **서버는 `repo_url` 의 `repo_ref` 를 받는다.** `docker-compose.tpot.yml` 과 `setup.sh` 의
  `SETUP_ES_URL` 지원, `tpotce/compose/aws_overlay.yml` 이 그 저장소에 있어야 허니팟 배치가 뜬다.
- 한국어 Kibana 는 T-Pot **첫 기동**에만 올라간다(tpotinit 동작). 이미 깔린 서버에는 Kibana 의
  Saved Objects → Import 로 `tpotce/docker/tpotinit/dist/etc/objects/kibana_export_ko.ndjson` 을 직접 올린다.
- **분류 모델은 저장소에 없다.** `models_s3_uri` 를 주지 않으면 규칙만으로 분류하는데,
  대시보드 모델 카드는 지표 파일을 읽어 LightGBM 이 있는 것처럼 보인다.
- **대시보드 회원 가입이 열려 있다.** 누구나 가입해 "더 깊게 분석"(Claude 호출)을 쓸 수 있다 —
  계정당 10분 5회 쿼터가 있지만, 평가자 IP 를 알면 `dashboard_cidrs` 를 좁힐 것.
- T-Pot 은 매일 새벽 임의 시각에 **스스로 재부팅**한다(T-Pot 설치기가 거는 cron). 대시보드 컨테이너는
  `restart: unless-stopped` 라 같이 돌아온다.
- 허니팟은 일부러 공격받는 서버다. 이 계정에 다른 자원을 두지 말 것.
- HTTP 로 연다(`COOKIE_SECURE=false`). TLS 를 앞에 두면 서버 `.env` 에서 true 로 바꾼다.
- user_data 를 고쳐도 서버는 그대로다. 다시 부트스트랩하려면
  `terraform apply -replace=aws_instance.app` (루트 볼륨의 수집 데이터가 사라진다).
- Checkov: `checkov -d infra/terraform --framework terraform` → 62 통과 · 4 skip
  (VPC flow log, 허니팟 포트 공개 3건 — 이유는 `network.tf` 주석).
