# Forensic Offline Search Web

CTF 현장에서 사용할 수 있는 한국어 디지털 포렌식 검색 자료입니다.
`dist/index.html`을 브라우저에서 열면 별도 서버나 인터넷 연결 없이 사용할 수 있습니다.

## 콘텐츠 수정과 검증

Node.js 20 이상이 필요하며 외부 npm 의존성은 없습니다.

```sh
npm run build
npm run validate
npm run test:search
npm run test:offline
```

엄격한 콘텐츠 검사는 `npm run validate:strict`로 실행합니다.
자료는 계속 작성·검토 중이므로 분석 결과는 원본 증거 및 도구의 실제 출력과 대조하세요.
내부 작업 큐, 개인 분석 자료와 원본 증거는 공개 저장소에 넣지 않습니다.
