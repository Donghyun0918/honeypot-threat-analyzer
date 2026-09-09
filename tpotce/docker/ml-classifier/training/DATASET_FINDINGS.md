# 학습 데이터 진단 (2026-08-31)

`data/ml-classifier/dataset/csv/` 의 허니팟 CSV 내보내기로 만든 학습셋
(`work/dataset.csv`, 298,841행)이 **실제 추론 입력과 구조적으로 달라
모델이 동작할 수 없다**는 결론과 근거를 기록한다.

재학습(라벨 재균형)으로는 해결되지 않는다. 시도했고 실패했다 — §4 참조.

---

## 1. 라벨이 `source_honeypot` 의 결정론적 함수

`rule_label.py` 는 대부분의 허니팟에 대해 이벤트 내용과 무관하게 상수를
반환한다 (`if src_hp == "p0f": return "Recon"`). 그 결과:

| honeypot | Recon | Brute Force | Malware | Intrusion | Etc | 합계 |
|---|---:|---:|---:|---:|---:|---:|
| cowrie | 49,412 | 582 | 6 | 0 | 0 | 50,000 |
| fatt | 50,000 | 0 | 0 | 0 | 0 | 50,000 |
| honeytrap | 50,000 | 0 | 0 | 0 | 0 | 50,000 |
| p0f | 50,000 | 0 | 0 | 0 | 0 | 50,000 |
| suricata | 40,137 | 0 | 5,937 | 3,926 | 0 | 50,000 |
| dionaea | 0 | 0 | 23,725 | 0 | 0 | 23,725 |
| sentrypeer | 0 | 18,694 | 0 | 0 | 0 | 18,694 |
| tanner | 2,569 | 0 | 0 | 0 | 0 | 2,569 |
| conpot | 1,020 | 0 | 0 | 0 | 0 | 1,020 |
| h0neytr4p | 0 | 783 | 0 | 0 | 0 | 783 |
| redishoneypot | 0 | 0 | 0 | 522 | 0 | 522 |
| miniprint | 0 | 0 | 0 | 0 | 410 | 410 |
| mailoney | 0 | 385 | 0 | 0 | 0 | 385 |
| adbhoney | 0 | 0 | 0 | 0 | 289 | 289 |
| honeyaml | 0 | 0 | 0 | 0 | 145 | 145 |
| elasticpot | 0 | 0 | 0 | 139 | 0 | 139 |
| heralding | 0 | 127 | 0 | 0 | 0 | 127 |
| ipphoney | 33 | 0 | 0 | 0 | 0 | 33 |

**18개 중 16개 허니팟이 라벨 하나에 100% 고정.** 내용이 실제로 라벨을
바꾸는 건 cowrie(582/50,000)와 suricata뿐이다.

→ 모델이 배울 수 있는 최선은 `(source_honeypot, event_type) → label` 룩업,
즉 **룰의 재현**이다. 기존 기록의 "0.998은 과대평가"가 정확했다.

## 2. 특징 16개 중 6개가 상수 0

`dataset.csv` 298,841행 기준 값이 0인 비율:

| 특징 | 0 비율 | 비고 |
|---|---:|---|
| `login_attempts` | 100.0% | CSV에 컬럼 자체가 없음 |
| `login_success` | 100.0% | 〃 |
| `has_reverse_shell` | 100.0% | 비0 **0건** |
| `has_curl` | 100.0% | 비0 **1건** |
| `has_wget` | 100.0% | 비0 **5건** |
| `special_char_cnt` | 100.0% | 비0 53건 |
| `cmd_length` | 83.2% | |
| `protocol` | 74.9% | |
| `dst_port` | 50.3% | |

**Malware·Intrusion·Brute Force를 실제로 구분하는 바로 그 특징들이
학습 내내 상수 0**이었다. 모델은 이 축을 쓸 수 없다.

## 3. 행동 이벤트에는 포트·프로토콜이 없다 (train/serve skew의 핵심)

`cowrie.csv` 92,861행:

| eventid | 행수 | dst_port |
|---|---:|---|
| `cowrie.session.connect` | 41,725 | `23.0` / `22.0` ✅ |
| `cowrie.session.closed` | 41,724 | – |
| `cowrie.login.failed` | 2,987 | **전부 빈값** |
| `cowrie.command.input` | 125 | **전부 빈값** |

- 전체의 **89.9%가 session connect/closed 노이즈**
- `input` 필드가 있는 행: **150건 (0.16%)**, 그중 wget/curl/chmod 포함 **16건**

포트·프로토콜은 `session.connect` 행에만 있고, 행동은 `login.failed` /
`command.input` 행에만 있다. **둘이 서로 다른 행에 흩어져 있어** 어느
쪽도 완전한 특징 벡터를 만들지 못한다.

### 그래서 같은 이벤트가 이렇게 갈린다

| | `dst_port` | `protocol` | `login_attempts` | `cmd_length` |
|---|---:|---:|---:|---:|
| **학습 행** (cowrie.login.failed) | 0 | 0 | 0 | 30~36 |
| **실 ES 문서** (같은 이벤트) | 22 | 6(ssh) | 25 | 0 |

특징 공간의 완전히 다른 영역이다. 모델은 실서비스 문서처럼 생긴 입력을
**한 번도 본 적이 없다.**

## 4. 재균형 재학습 시도 결과 — 실패

`rebalance.py` 로 (label, honeypot) 셀 상한을 걸어 지름길을 차단했다:

- Brute Force 내 sentrypeer 비중 **90.9% → 51.6%**
- cowrie 내 Recon:Brute Force **85:1 → 641:582 (약 1:1)**
- 최종 17,382행, holdout accuracy **0.9971**, macro-F1 0.9977

그러나 정규 케이스 검증은 **3/6**으로 재균형 전과 동일:

| 케이스 | 룰 | 모델(v2) | 신뢰도 |
|---|---|---|---:|
| cowrie 로그인실패 25회 | Brute Force | **Recon** ✗ | 99.8% |
| cowrie wget 멀웨어 | Malware | **Recon** ✗ | 100.0% |
| cowrie 리버스셸 | Intrusion | **Recon** ✗ | 65.2% |
| ConPot 포트스캔 | Recon | Recon ✓ | 100.0% |
| dionaea 멀웨어 | Malware | Malware ✓ | 100.0% |
| p0f 핑거프린팅 | Recon | Recon ✓ | 99.8% |

라벨 불균형이 아니라 **§2·§3의 특징 결손**이 원인이므로 재균형으로는
고쳐지지 않는다. 0.9971은 학습 분포 안에서만 유효하다.

---

## 4-B. 시나리오 B (세션 조인) 시도 결과 — 개선했으나 천장 확인

§5의 선택지 B를 실제로 구현했다. `session_join.py` 가 라이브 Logstash가
하는 일을 CSV에서 재현한다: 세션의 connect 행에서 포트·프로토콜을 거둬
같은 세션의 모든 이벤트 행에 전파하고, 세션당 `login.failed` 수를 세어
`login_attempts` 를 만들고, 89.9%를 차지하던 session connect/closed
북키핑 행을 (속성을 거둔 뒤) 버린다.

**cowrie 행이 실제로 복원됐다:**

| | 조인 전 | 조인 후 |
|---|---:|---:|
| 행 수 | 50,000 | 3,217 |
| `dst_port` 비0 | 48.3% | **100%** |
| `login_attempts` 비0 | 0% | **93.3%** |
| `cmd_length` 비0 | – | **100%** |
| 라벨 | Recon 49,412 / BF 582 | **BF 3,073** / Recon 128 |

**함께 고친 실제 버그 2건** (둘 다 학습·추론 양쪽에 영향):

1. `_intval("23.0")` 이 `int()` 예외로 **0을 반환** — CSV 경로의 모든 포트와
   카운트가 0이 되는데 라이브 ES 문서(정수)는 정상이라, 같은 이벤트를 두
   경로가 다르게 봤다. `int(float(v))` 로 수정.
2. `_command_text()` 가 `payload_printable` 을 안 읽음 — suricata는 공격
   명령을 여기에 담는다. cowrie가 wget 10행·리버스셸 0행을 낼 때 suricata
   payload에는 891건·443건이 있었다. 필드 목록에 추가.

**실제 ES 문서 127건 기준 룰 대비 일치율:**

| 모델 | 일치 | 주요 오류 |
|---|---:|---|
| v2 (조인 전) | 35.4% | BruteForce→Recon 33 · Malware→Recon 24 |
| v3 (세션 조인) | **61.4%** | Intrusion→Malware 25 · Malware→Recon 24 |
| v4 (+payload) | 61.4% | 동일 |

**v4가 v3를 못 넘은 이유** — 남은 오류는 cowrie `command.input` 문서인데
그 문서엔 `payload_printable` 이 없다. 게다가 payload로 얻은 리버스셸
384행 중 **322행이 `Recon` 라벨**이다: suricata 룰 라벨은
`alert.category` 에서 오고 그것이 payload 내용과 어긋난다. 특징이
생겨도 라벨이 그 특징을 부정하므로 모델은 "리버스셸 → Recon" 을 배운다.

**천장:** 라벨이 룰에서 나오므로 모델의 최대치는 룰 재현(100%)이고,
현재 61.4%다. 켜면 운영이 나빠진다.

**단, 룰이 못 하는 것 하나는 된다** — 정상 HTTP/HTTPS 트래픽을
`Normal` 로 100% 신뢰도로 분류한다(룰은 `Recon` 이라 답한다). 다만
허니팟 특성상 정상 트래픽이 거의 없어 실익은 제한적이다.

## 5. 결론과 선택지

현재 데이터로 학습한 ML 분류기는 **룰보다 나쁘다**. 룰은 6/6 정확하다.
그래서 운영은 룰 모드로 두었다 (`models/disabled-recon-biased/` 참조).

실제로 ML을 켜려면 셋 중 하나가 필요하다:

**A. 실 ES 문서로 학습 (권장)**
`build_dataset.py --from-es` 로 `logstash-*` 에서 직접 뽑는다. T-Pot logstash가
이미 포트·프로토콜·행동 필드를 한 문서에 합쳐놓으므로 §3의 분산 문제가 없고
추론 입력과 분포가 같다. 단 의미 있는 양이 쌓일 때까지 허니팟을 실제로
운영해야 한다.

**B. CSV를 세션 단위로 조인해 복원** — ✅ 구현·측정 완료 (§4-B)
`session_join.py` 로 35.4% → 61.4%. 특징 결손은 실제로 해소됐으나 약라벨이
payload 내용과 모순되어 천장에 걸렸다. 운영 투입 기준에는 미달.

**C. 룰 유지 (현재)**
ML 분류기를 졸작 산출물에서 빼거나, "룰 기반 분류 + LLM 해설"로 주제를
재정의한다. 가장 정직하고 지금 동작한다.

## 재현

```bash
# 재균형
python rebalance.py --csv work/dataset.csv --normal work/normal.csv \
    --encoders work/encoders.json --out work/balanced_v2.csv \
    --cap-per-cell 2000 --cap-per-label 4000

# 학습 (호스트에 joblib/pandas 없으면 컨테이너 사용)
docker build -f train.Dockerfile -t tpot/ml-training:local .
docker run --rm -v "$PWD/training:/train:ro" -v "$PWD/data/.../work:/work" \
    tpot/ml-training:local \
    python /train/train.py --csv /work/balanced_v2.csv \
        --encoders /work/encoders.json --out-dir /work/models_v2
```
