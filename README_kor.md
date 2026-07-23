# DEEP SAT EXPLOIT

**지상국 로그인 페이지부터 위성 탑재 컴퓨터(OBC) 코드 실행까지 — 풀체인 위성 해킹 CTF**

## 소개

**DEEP SAT EXPLOIT**은 실제 우주 임무 명령 경로 전체를 공격자가 직접 따라가는 4단계 CTF 챌린지입니다.

경로: 지상국 공개 웹 → 인증된 명령 업링크 → 무선 통신 구간 → 비행 소프트웨어 명령 라우터 → 탑재 컴퓨터(OBC) 메모리

실제 임무와 마찬가지로, 위성에 닿는 유일한 경로는 **지상 세그먼트와 짧은 가시선(AOS) 구간**을 통과하는 것뿐입니다. 각 단계의 침투가 다음 단계의 크리덴셜이 되기 때문에, 4개의 버그가 **하나의 연속된 스토리**가 됩니다:

> 웹 세션 ⟶ 명령 권한 ⟶ 버스 라우팅 ⟶ 앱 메모리 안전성

마지막 단계는 **비행 소프트웨어 소프트웨어 버스를 넘나드는 메모리 손상 샌드박스 탈출**입니다. 브라우저/OS의 IPC 메시지 샌드박스 탈출과 구조가 동일하지만, 여기서 "샌드박스"는 NASA cFS 스타일의 비행 앱이고, "IPC"는 위성 소프트웨어 버스입니다.

모든 구성은 실제 시스템을 기반으로 합니다 — 지상 세그먼트는 [Yamcs](https://github.com/yamcs/yamcs), 비행 소프트웨어는 [NASA cFS](https://github.com/nasa/cFS) 형태이며, 단순화되었지만 실제 CCSDS 원격명령 포맷을 충실히 구현했습니다.

> ⚠️ **교육/CTF 전용 의도적 취약 소프트웨어입니다.** 공개 인터넷에 노출하지 마세요.

## 풀 체인 — 지상국 → 위성

브라우저 하나로 시작해서 위성 위에서 셸을 얻는 것으로 끝납니다. 각 단계가 다음 단계를 잠금 해제합니다:

### Stage 1 — GROUND ZERO

**서비스:** `ground-station` (Flask), http://localhost:8080

세션 쿠키는 JWT입니다. 공개 `guest/guest` 계정으로 실제 HS256 토큰이 발급됩니다. 운영자 기능(`role == "operator"`)이 필요한 명령 콘솔, 업링크 키, 펌웨어 다운로드에 접근하려면 `alg: "none"` (서명 없음) 토큰을 위조해야 합니다.

**취약점:** JWT 검증기가 `alg:none`을 허용함. HMAC 시크릿은 부팅마다 무작위이므로 브루트포스는 불가.

**익스플로잇:**
```python
import base64, json
b = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()
tok = b({"alg":"none","typ":"JWT"}) + "." + b({"user":"admin","role":"operator"}) + "."
# Cookie: session=<tok>
```

### Stage 2 — SIGNAL PASS

**서비스:** `uplink` (raw TCP), `localhost:9010`

업링크 릴레이는 실제 저궤도(LEO) 위성의 가시 구간을 모델링합니다: **약 15초의 AOS**(신호 획득) 동안만 명령이 전달되고, 이후 **약 45초의 LOS** 동안은 모든 것이 차단됩니다. 유효한 **CCSDS 원격명령**을 프레이밍해서 가시 구간 내에 전달해야 합니다.

### Stage 3a — BUS HIJACK

**서비스:** `flight-sw` (내부 전용)

cFS 스타일의 비행 소프트웨어는 **전체 11비트 메시지 ID**로 앱을 라우팅하지만, **잘린 하위 1바이트**로만 권한을 확인합니다. 하위 바이트가 비제한 앱과 충돌하는 특권 앱은 원시 업링크에서 접근 가능해집니다 — 전형적인 파서 차이/라우트 혼동 취약점입니다.

### Stage 3b — OBC ESCAPE

**서비스:** `flight-sw` (내부 전용)

이제 접근 가능해진 특권 앱 중 하나가 명령 페이로드를 고정 크기 스택 버퍼에 **경계 검사 없이** 복사합니다. 저장된 반환 주소를 오버플로우하고(`-no-pie`, 스택 카나리 없음, 심볼 포함) **부팅 경로에서만 호출되어야 할 핵심 비행 실행 루틴으로 ret2win** — OBC에서 코드 실행.

```
  ┌────────────┐   HTTP     ┌──────────────┐  CCSDS/TC     ┌───────────────┐   소프트웨어 버스   ┌──────────────┐
  │  공격자    │ ─────────▶ │ 지상국       │ ──(15s AOS)──▶│ 업링크 릴레이 │ ───(msgid)───────▶ │  비행 SW     │
  │            │            │ 웹           │               │ (가시성)      │                    │  (cFS-like)  │
  └────────────┘            └──────────────┘               └───────────────┘                    └──────────────┘
   Stage 1: GROUND ZERO      Stage 2: SIGNAL PASS            Stage 3a: BUS HIJACK
   alg=none JWT → 운영자     15초 가시 구간 타기             ACL 혼동 → Stage 3b: OBC ESCAPE
```

## 실행 방법

```bash
docker compose up --build
```

| 서비스 | URL / 엔드포인트 | 역할 |
|---|---|---|
| 지상국 (웹 미션 컨트롤) | http://localhost:8080 | **여기서 시작** |
| 업링크 릴레이 (raw TCP) | `localhost:9010` | stage 2+ |
| 스코어보드 + 3D 글로브 | http://localhost:8000 | 미션 모니터링 및 플래그 제출 |

`flight-sw` OBC는 외부에서 직접 접근 불가 — 실제 위성처럼 내부 `spacelink` 네트워크를 통해 릴레이하고만 통신합니다.

## 디렉토리 구조

```
.
├── ground-station/     # Stage 1 — GROUND ZERO  (Flask 웹 앱)
├── uplink/             # Stage 2 — SIGNAL PASS  (CCSDS 릴레이)
├── flight-sw/          # Stage 3a/3b — BUS HIJACK / OBC ESCAPE  (cFS 스타일 비행 SW)
├── scoreboard/         # 3D 상황인식 글로브 + 플래그 제출
├── solution/           # 출제자 익스플로잇 스크립트
├── config/             # 공유 설정
├── docs/               # 지원 이미지 및 다이어그램
└── docker-compose.yml
```

## 단계별 요약

| 단계 | 이름 | 서비스 | 취약점 유형 |
|---|---|---|---|
| 1 | GROUND ZERO | ground-station | JWT `alg:none` |
| 2 | SIGNAL PASS | 업링크 릴레이 | CCSDS 프레이밍 + 타이밍 |
| 3a | BUS HIJACK | flight-sw | ACL / msgid 잘림 |
| 3b | OBC ESCAPE | flight-sw | 스택 버퍼 오버플로우 → ret2win |
