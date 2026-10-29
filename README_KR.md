# Interlock-128

[English](README.md)

128비트 블록·256비트 키·28라운드를 연구 기준으로 삼는 실험용 블록 암호다.
C11 구현 한 개와 [규범 명세](docs/spec_ko.md) 한 개만 유지한다.
보안 강도와 독창성은 미확정이며 실제 비밀 보호에 사용하지 않는다.
모드, 패딩, 파일 암호화, 인증, GUI와 서버는 범위 밖이다.

[연구 기록](docs/security_ko.md)에서 증명·실험·미해결 문제를 구분한다.
과거 설계는 Git 이력으로만 추적하고 다른 코어를 함께 배포하지 않는다.
현재는 C11 암복호화, 키 소거, 독립 KAT·중간값 대조와 조기 구조 분석까지
구현했다. 추가로 8라운드 prefix까지 제한된 차분·회전·적분 검사를 제공한다.
공개 API는 고정 28라운드이며 축소라운드는 시험 전용이다.

## 빌드와 검증

Linux의 C11 컴파일러·Make·Python 3.10 이상이 필요하다.
Python은 시험·연구에만 사용하며 기본 검증은 표준 라이브러리만 사용한다.
정적 라이브러리는 Python이나 외부 암호 라이브러리에 의존하지 않는다.

```sh
make all             # build/libinterlock.a
make check           # C KAT·부정 입력 및 독립 Python 대조
make research        # 9개 제한된 실험, build/summary.json 및 개별 보고서
make sanitize        # ASan·UBSan으로 독립 C 시험
```

컴파일러·옵션을 바꿀 때는 `make clean`을 먼저 실행한다.
`make sanitize`는 자동 정리 후 C 실행 파일을 검사한다.
이후 Python 검증으로 돌아갈 때도 정리하여 일반 시험용 공유 라이브러리를
다시 빌드한다. 분석 JSON은 CI에서도 실행별 artifact로 7일간 제공한다.

정확한 SMT 연구에는 선택적 Z3 의존성을 설치한다.

```sh
python3 -m pip install -r research/requirements-smt.txt
make smt-check smt-research
```

SMT 7개 실험은 모델 일치성·투영 계수·외부 FM 서브키 추론·28라운드까지의
고정 키 실행 가능성을 검사한다. 출력 역변환을 적용한 FM 복원은 시험한
3키에서 첫 라운드 서브키 전체를 복원하고 새 블록·유일성을 확인했다.
1라운드 공격에 한정되며 12/20/28라운드의 낮은 차분 무게 탐색은 미해결이다.
[추가 공격 기록](docs/attacks_ko.md)과 [페이즈·작업 진행표](docs/research_status_ko.md)에서
조건과 남은 과제를 확인할 수 있다. JSON·SMT2는 CI artifact로 7일간 제공한다.

## API 계약

`include/interlock.h`를 포함하고 정적 라이브러리를 링크한다.
0 초기화한 `interlock_ctx`에 `interlock_init(&ctx,key,32)`를 호출한 후,
`interlock_encrypt_block(&ctx,out,out_capacity,in,16)` 또는
`interlock_decrypt_block`을 호출한다. 사용 후 `interlock_clear(&ctx)`로 소거한다.
반환값은 성공 0, 인수 오류 -1, 미준비 컨텍스트 -2다.

출력 capacity는 16 이상이어야 하며 첫 16바이트만 변경한다.
블록 오류 시 출력은 변경하지 않는다. 입력·출력의 동일/부분 중첩은 허용하고
출력과 컨텍스트의 중첩은 거부한다. init 실패는 NULL이 아닌 컨텍스트를
소거한다. 실제 할당 크기·포인터 유효성·스레드 동기화는 호출자가 보장한다.

1~3라운드 구별식, 격리된 FS 내부 관측의 서브키 노출 제약과 FM의 강한
국소 편향을 연구 기록에 남겼다. 전체 재현은 8251624회 블록 오라클 평가이며
부품 함수 평가는 별도다. 보고서의 소스/바이너리 지문·완료 상태·쿼리 원장이
서로 다르거나 짧은 회귀 결과가 섞이면 `make research`가 중단된다.
실행 결과는 `build/`와 CI artifact로 제공하며 저장소에 원시 로그를 넣지 않는다.

4~8라운드의 제한된 빈도 검사와 기능 검증은 28라운드 보안성 증명이 아니다.
32비트·빅엔디언 실행, 생성 코드/타이밍 누출, 전체 공격 비용과 외부 독립 검토는
아직 검증하지 않았다.
