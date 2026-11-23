# tools

## pretty.py — 분석 결과 표 보기

`main.py`가 한 줄에 하나씩 출력하는 JSON을 읽기 쉬운 표로 바꿔 줍니다.
`main.py`와 파서는 건드리지 않고 출력만 읽으므로, 결과 화면 캡처나 발표 설명용으로 씁니다.

저장소 루트에서 실행합니다.

```bash
# 실시간: 캡처 결과를 파일로 저장하면서 표로 보기
sudo python3.12 main.py -i eth0 | tee result.jsonl | python3.12 tools/pretty.py

# 저장해 둔 결과를 표로 보기
python3.12 tools/pretty.py result.jsonl
```

| 옵션 | 설명 |
|---|---|
| `--all` | HTTP·DNS·SMTP 포트(53, 80, 8000, 25, 2525)가 아닌 패킷도 표시 |
| `--no-color` | 색 없이 출력 (송신 초록, 수신 파랑이 기본) |

표시 열: No, 시각(KST), 방향(송신/수신), 출발지 → 목적지, 계층(TCP/HTTP 등), TCP 플래그, SEQ, ACK, 설명

설명 열은 연결마다 번호를 붙이고 단계를 표시합니다.

- TCP 연결 설정: `① 연결 요청` → `② 연결 수락` → `③ 연결 확립` (3-way handshake)
- 데이터 전송: `HTTP 요청: GET`, `HTTP 응답: 200`, `데이터 전송 (이어지는 조각)`, `수신 확인 (ACK)`
- 연결 해제: `연결 해제 요청 (FIN 1)` → `상대도 해제 (FIN 2)` → `연결 해제 완료 (마지막 ACK)`
- UDP: `DNS 질의 (ID 0x....)`, `DNS 응답 (ID 0x...., rcode 0)`
- SMTP: `SMTP 명령: EHLO`, `SMTP 응답: 250`

SEQ·ACK는 절대값입니다. Wireshark와 비교할 때는 Wireshark의
TCP 설정에서 `Relative sequence numbers`를 끄면 같은 값이 보입니다.

테스트: `python3.12 -m unittest tests.test_pretty -v`
