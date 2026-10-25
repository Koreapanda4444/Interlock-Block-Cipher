# Interlock-128

[English](README.md)

128비트 블록·256비트 키·28라운드를 연구 기준으로 삼는 실험용 블록 암호다.
C11 구현 한 개와 [규범 명세](docs/spec_ko.md) 한 개만 유지한다.
보안 강도와 독창성은 미확정이며 실제 비밀 보호에 사용하지 않는다.
모드, 패딩, 파일 암호화, 인증, GUI와 서버는 범위 밖이다.

[연구 기록](docs/security_ko.md)에서 증명·실험·미해결 문제를 구분한다.
과거 설계는 Git 이력으로만 추적하고 다른 코어를 함께 배포하지 않는다.
현재는 C11 암복호화, 키 소거, 독립 KAT·중간값 대조와 조기 구조 분석까지
구현했다. 공개 API는 고정 28라운드이며 축소라운드는 시험 전용이다.

## 빌드와 검증

Linux의 C11 컴파일러·Make·Python 3.10 이상이 필요하다.
Python은 시험·연구에만 사용하며 외부 Python 패키지는 필요 없다.
정적 라이브러리는 Python이나 외부 암호 라이브러리에 의존하지 않는다.

```sh
make all             # build/libinterlock.a
make check           # C KAT·부정 입력 및 독립 Python 대조
make research        # 제한된 구조 분석, build/analysis.json
make sanitize        # ASan·UBSan으로 독립 C 시험
```

컴파일러·옵션을 바꿀 때는 `make clean`을 먼저 실행한다.
`make sanitize`는 자동 정리 후 C 실행 파일을 검사한다.
이후 Python 검증으로 돌아갈 때도 정리하여 일반 시험용 공유 라이브러리를
다시 빌드한다. 분석 JSON은 CI에서도 실행별 artifact로 7일간 제공한다.

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

1라운드 구별 공격과 격리된 FS 내부 관측의 서브키 노출 제약은 연구 기록에
증명·재현했다. 4라운드 빈도 검사와 기능 검증은 28라운드 보안성 증명이 아니다.
32비트·빅엔디언 실행, 생성 코드/타이밍 누출, 전체 공격 비용과 외부 독립 검토는
아직 검증하지 않았다.
