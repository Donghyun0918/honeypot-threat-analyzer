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

---

## 6. 실 ES 문서로 재학습 — §5-A 실행 결과 (2026-09-14)

§5 에서 "A. 실 ES 문서로 학습 (권장)" 이라 적어둔 것을 실제로 했다.
**가설이 맞았다.** 특징 결손은 CSV 내보내기의 문제였고, ES 문서로 학습하니
사라진다.

### 데이터

AWS EC2 에 띄웠던 T-Pot 이 **2026-04-27 ~ 05-06 (10일)** 동안 받은 실제 공격
로그다. `logs/` 의 원본 JSON 을 T-Pot 의 logstash 설정 그대로 태워 색인했다
(`docker/elk/logstash/import/`). p0f 170만 행은 수동 핑거프린팅이라 제외.

> **집계 범위.** 아래 수치는 `ml-analysis-*` 를 **수집 창(04-27 ~ 05-06)으로
> 한정해** 센 값이다. 인덱스 전체를 그냥 세면 09-09 시연 표본 1,736건과 지금
> 들어오는 라이브 트래픽이 함께 잡힌다 — 처음에 그렇게 재서 1,028,698 /
> 24,373 / 45,744 로 적었다가 되돌렸다. 창을 고정해야 재현된다.
>
> 창 바깥으로 `logstash-1970.01.01` 15,376건이 더 있다. honeytrap 의
> `attackers.json`(누적 집계 파일)이라 타임스탬프가 없어 epoch 0 으로 떨어진
> 것이고, 개별 공격 이벤트가 아니므로 분류 대상이 아니다.

| | |
|---|---:|
| 색인 문서 | 1,026,903 |
| 고유 공격 IP | 24,346 |
| geoip 적용 | 840,260 (81.8%) |
| 수집 지점 종류 | 18 (허니팟 16 + Suricata + Fatt) |

출발지 상위: 미국 299,877 · 브라질 99,817 · 영국 55,733 · 중국 47,853.

규칙 라벨 분포 (전량):

| 라벨 | 건수 | 점수 | 모델 이견 |
|---|---:|---:|---:|
| Etc | 566,099 | 0 | 169 (0.03%) |
| Recon | 392,668 | 32 | 107,257 (27.3%) |
| Malware | 24,455 | 92 | 33 (0.13%) |
| Brute Force | 23,061 | 65 | 18,593 (80.6%) |
| Intrusion | 20,620 | 85 | 704 (3.4%) |

수집 지점별로는 Suricata 727,868 · Cowrie 92,859 · Honeytrap 79,092 ·
기타 15종 127,084. **Cowrie 의 Intrusion 은 0건**이다 — 10일 내내 cowrie
세션에서 규칙이 침입으로 올린 건이 없었다. §4 에서 학습셋의 cowrie Intrusion
공백을 지적했는데, 그건 표본 추출 문제가 아니라 **원 데이터가 그렇다**는 뜻이었다.

### 학습

```
build_dataset.py --source-index 'logstash-*' --since now-1y --max 250000
    → 250,000행 (가장 이른 04-27~04-29 구간, @timestamp asc)
train.py --csv real.csv
    → CV acc 0.9997±0.0000 · macro-F1 0.9988±0.0002
    → hold-out(학습셋 내부 20%) acc 0.9995 · macro-F1 0.9981
```

**0.9995 는 여전히 믿을 숫자가 아니다.** 라벨이 규칙에서 나오므로 이건
"규칙을 외웠다" 는 뜻이고, §4 에서 0.9971 이 그랬듯 학습 분포 안에서만 유효하다.

### 진짜 측정 — 학습에 쓰지 않은 실 문서 20만 건

04-30 이후 구간에서 200,000건을 따로 뽑아(`eval_vs_rule.py`) 규칙과의 합의율을
쟀다. §4-B 가 127건으로 쟀던 것을 같은 방식으로 확대한 것이다.

| 모델 | micro | macro | Brute Force | Etc | Intrusion | Malware | Recon |
|---|---:|---:|---:|---:|---:|---:|---:|
| v4 (CSV 세션조인 학습) | 77.1% | 51.1% | 6.9% | 99.4% | 93.6% | 3.0% | 52.9% |
| **v5 (실 ES 문서 학습)** | **92.5%** | **91.7%** | **78.4%** | 99.4% | **97.4%** | **100.0%** | **83.5%** |

macro 기준 **51.1% → 91.7%**. 클래스별로 보면 차이가 어디서 났는지 분명하다:

- **Malware 3.0% → 100.0%.** v4 는 Malware 3,450건 중 3,328건을 Intrusion 으로
  불렀다. 학습 CSV 에서 두 클래스를 가르는 특징(`has_wget`·`has_curl`·
  `has_reverse_shell`)이 전부 상수 0 이었으니 당연한 결과다(§2).
- **Brute Force 6.9% → 78.4%**, **Recon 52.9% → 83.5%.**
  `login_attempts` 가 CSV 에서 100% 0 이었던 것이 ES 문서에는 들어 있다.

남은 오답은 한 곳에 몰려 있다 — **Recon → Brute Force 13,880건**. 나머지
오답은 전부 네 자리 수 미만이다.

### 그래서 모델을 켜야 하는가 — 아니다

**92.5% 는 "규칙을 얼마나 잘 흉내내는가" 이지 "공격을 얼마나 잘 맞추는가" 가
아니다.** 정답이 규칙에서 나오고 규칙은 정규 케이스 6/6 이므로, 모델을 켜면
7.5% 만큼 나빠진다. 상한은 여전히 규칙 재현 100% 다.

달라진 것은 **원인 규명**이다. §2·§3 이 지목한 특징 결손은 실제로 원인이었고
(그래서 실 문서로 학습하니 51.1% → 91.7%), §4 의 재균형이 실패한 이유도
확인됐다 — 라벨 불균형이 아니라 특징이 없었던 게 맞다.

모델이 규칙을 이기려면 **라벨이 규칙 바깥에서 와야 한다.** 후보는 Suricata 의
`alert.signature_id` / `alert.category` / `alert.severity` (Emerging Threats
룰셋이 준 외부 라벨)인데, 그러면 이번엔 "Suricata 재현" 이 되므로 같은 순환이다.
정직한 결론은 §5-C 그대로다: **룰 기반 분류 + 한국어 LLM 해설**로 주제를 두고,
ML 은 "왜 여기서 안 되는가" 를 측정한 결과로 남긴다.

### 덤 — LLM 처리량 실측

같은 색인으로 llm-analyzer 를 돌려 처리 속도를 쟀다. `exaone3.5:7.8b` 를
CPU 로 돌려 10건 배치 두 번에 **건당 60.3초 · 61.4초** (README 의 27초는 3B
기준이다). 하루 1,416건이고, 고위험 45,075건을 전부 해설하려면 **31.8일**이
걸린다. 게이트(`MIN_SCORE=70`)가 없으면 1,026,903건에 725일이다 —
게이트는 최적화가 아니라 파이프라인이 성립하기 위한 조건이다.

### 그래서 v5 를 활성 모델로 올렸다 (2026-09-15)

윗 문단의 "켜야 하는가 — 아니다" 는 **라벨을 모델에 맡기느냐**에 대한 답이고,
그건 여전히 아니다. 하지만 `classify.py` 에서 모델은 이미 라벨을 뒤집지 못하고
`ml_label_raw` / `ml_dissent` 로 교차검증만 한다. 즉 실제 선택지는 "켜냐 마냐"가
아니라 **어느 모델로 교차검증하느냐** 였고, 그 자리에 v4 가 남아 있었다.

v4 로 두면 불일치 표시의 대부분이 모델 쪽 오답이 된다 — 홀드아웃 20만 건에서
v4 는 Malware 3,450건 중 3,328건을 Intrusion 으로, Recon 84,098건 중 28,756건을
Malware 로 불렀다. 검토 큐가 그 오답으로 채워진다.

그래서 `models/` 를 v5 로 교체하고 v4 는 `models/superseded-v4-csv-sessionjoin/`
에 사유와 함께 보존했다. 교체 후 같은 홀드아웃으로 재측정해 92.5% / macro 91.7%
를 확인했다(`eval_vs_rule.py`).

대시보드 "현재 분류 모델" 카드도 같이 고쳤다. 그전까지 학습셋 내부 수치
(99.9% · Macro-F1 99.8%)를 내보내고 있었는데, 그건 이 문서가 두 번 못 박은
"규칙을 외웠다" 는 숫자다. 이제 `active-metrics.json` 의 `holdout_vs_rule` 을
`/api/model` 로 흘려 **미학습 실문서 20만 건 기준 92.5%** 를 먼저 보여준다.

> 기존 `ml-analysis-*` 문서는 재분류하지 않았다. 규칙 라벨(`ml_label`)과
> `mitre_score` 는 모델과 무관하므로 바뀌지 않고, 달라지는 것은 v5 이후
> 신규 문서의 `ml_label_raw` / `ml_dissent` 뿐이다. 과거분까지 맞추려면
> `data/ml-classifier/cursor.json` 을 지우고 전량 재처리해야 한다(100만 건).

### 정정 — 92.5% 는 측정 아티팩트였다 (2026-09-15)

전량 재분류 후 라이브 합의율을 재보니 **99.8%** 였다. 학습에 쓰지 않은 구간
(04-30~05-06, 634,271건)만 떼어봐도 **99.9%** 다. 위 표의 92.5% 와 7%p 넘게
차이가 나서 측정 경로를 뒤졌다.

원인은 홀드아웃 CSV 였다. `build_dataset.py` 는 호출할 때마다 인코더를 **자기가
본 문서에서 새로 만든다**(`--encoders-in` 같은 옵션이 없다). 그래서
`--out holdout.csv --encoders-out enc_holdout.json` 로 뽑은 홀드아웃은
학습셋과 다른 인코더를 갖게 됐다:

```
event_type 47종 중 22종의 코드가 어긋남
  "AST I20100"      학습=1   홀드아웃=없음   ← 홀드아웃 구간에 이 이벤트가 없어서
  "CONNECTION_LOST" 학습=2   홀드아웃=1      ← 이후 코드가 전부 1씩 밀림
  "NEW_CONNECTION"  학습=3   홀드아웃=2
  …
20만 행 중 60,176행이 모델이 배운 적 없는 코드로 들어갔다
```

홀드아웃 CSV 의 `event_type` 을 학습 인코더 기준으로 되돌리고 다시 재니:

| 모델 | micro | macro | Brute Force | Etc | Intrusion | Malware | Recon |
|---|---:|---:|---:|---:|---:|---:|---:|
| **v5 (교정 후)** | **99.9%** | **99.2%** | 98.8% | 100.0% | 97.3% | 100.0% | 100.0% |
| v5 (교정 전) | 92.5% | 91.7% | 78.4% | 99.4% | 97.4% | 100.0% | 83.5% |

"Recon → Brute Force 13,880건" 이라던 오답 덩어리는 모델의 약점이 아니라
**밀린 코드** 였다. 교정 후 남은 오답은 전부 세 자리 수 미만이다.

**v4 의 51.1% 도 같은 이유로 공정한 비교가 아니다.** v4 는 CSV 세션조인
데이터셋의 또 다른 인코더로 학습됐으므로 어느 쪽 홀드아웃 인코딩으로 재도
맞지 않는다. 두 모델을 같은 조건에서 비교할 수 있는 유일한 숫자는 **실제
추론 경로의 합의율** 이고, 전량 재분류로 그걸 얻었다:

| 모델 | 문서 | 합의 | 불일치 | 합의율 |
|---|---:|---:|---:|---:|
| v4 | 1,028,698 | 901,286 | 127,137 | 87.6% |
| **v5** | 1,028,698 | 1,026,528 | **2,170** | **99.8%** |

v4 가 남긴 `ml_label_raw` 에는 v5 에 존재하지도 않는 `Normal` 이 418건 있었다.
재분류로 사라졌다. `rule(low-conf)` 275건도 0 이 됐다.

**결론은 바뀌지 않는다.** 99.8% 는 "규칙을 얼마나 잘 흉내내는가" 이고 상한은
여전히 규칙 재현 100% 다. 달라진 건 숫자의 방향이 아니라 **왜 92.5% 였는지**
가 모델 성능이 아니라 측정 버그였다는 점이다. 교훈: 학습과 평가가 카테고리
인코딩을 공유하지 않으면 그 평가는 모델을 재지 못한다.

**고쳤다 (2026-09-15).** `build_dataset.py --encoders-in` 을 추가했다. 기존
인코더를 그대로 쓰고(새로 만들지 않고), 그 인코더가 새 문서를 얼마나 덮는지
— 미지 카테고리가 몇 종 · 몇 행인지 — 를 경고로 찍는다. 코드 0 은 "모름" 이자
정렬 첫 카테고리의 코드이기도 해서 조용히 넘어가면 안 되는 수치다.
`--encoders-in` 없이 부를 때도 "이 CSV 는 여기서 만든 코드 체계를 쓴다" 는
주의를 찍는다.

`--encoders-in` 으로 홀드아웃을 다시 뽑아 검증했다:

```
Reusing encoders ← /work/encoders.json  (proto=7, hp=18, event=47)
  WARNING: event_type 미지 카테고리 2종 → 3행 (0.0%) 이 코드 0 으로 떨어진다:
           'cowrie.client.var', 'cowrie.session.file_download'
→ 수동 교정본과 event_type 불일치 0행 / 200,000행
→ eval_vs_rule: v5 micro 99.9% · macro 99.2% (재현)
```

잘못된 인코딩으로 만들어진 옛 `holdout.csv` · `enc_holdout.json` 은 같은
함정이므로 교체했다. 이제 `enc_holdout.json` 은 `encoders.json` 과 동일하다.

### 재현

```bash
# 1) 보관 로그 스테이징 (.gz·날짜별 로테이션을 하나로 합친다)
python3 docker/elk/logstash/import/stage_logs.py \
    --src /path/to/logs --dst /path/to/logs-staged

# 2) logstash 로 색인 (MY_EXTIP 은 센서 IP)
docker run -d --name logstash-import --network capstone-dev_default \
    -e TPOT_TYPE=HIVE -e MY_EXTIP=<sensor-ip> -e MY_INTIP=<sensor-ip> \
    -e MY_HOSTNAME=tpot-sensor -e LS_JAVA_OPTS="-Xms1024m -Xmx1024m" \
    -v /path/to/logs-staged:/data:ro \
    -v $PWD/docker/elk/logstash/import/logstash-import.conf:/etc/logstash/logstash.conf:ro \
    ghcr.io/telekom-security/logstash:24.04.1

# 3) 학습셋 · 홀드아웃
docker run --rm --network capstone-dev_default -e PYTHONPATH=/dist \
    -v $PWD/docker/ml-classifier/training:/train:ro \
    -v $PWD/docker/ml-classifier/dist:/dist:ro \
    -v $PWD/data/ml-classifier/work-real:/work \
    tpot/ml-training:local python /train/build_dataset.py \
        --es http://elasticsearch:9200 --since now-1y --max 250000 \
        --out /work/real.csv --encoders-out /work/encoders.json
#   홀드아웃은 한 번 더 — 학습 인코더를 반드시 --encoders-in 으로 넘긴다.
#   (안 넘기면 코드 체계가 새로 만들어져 평가가 성립하지 않는다 — 위 정정 참조)
#        --since 2026-04-30 --max 200000 --out /work/holdout.csv \
#        --encoders-in /work/encoders.json --encoders-out /work/enc_holdout.json

# 4) 학습 + 규칙 대비 측정
    … python /train/train.py --csv /work/real.csv --encoders /work/encoders.json \
        --out-dir /work/models_real
    … python /train/eval_vs_rule.py --csv /work/holdout.csv \
        --model "v4=/data/models/multi_model.pkl" \
        --model "v5=/data/work-real/models_real/multi_model.pkl"
```
