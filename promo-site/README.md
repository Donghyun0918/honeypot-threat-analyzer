# 소개 웹사이트 (교수 요구사항 #4·#5)

## 이 폴더의 구조

```
index.html     원본. <title> 로 시작하는 **조각**이다 — doctype·html·head·body 가 없다.
               Artifact 호스트가 감싸주는 형식이라 그렇다. 내용은 여기서만 고친다.
build.sh       조각을 완전한 문서로 감싸 dist/ 를 만든다.
dist/          배포본. build.sh 가 만든다. **저장소에 함께 둔다** —
               docs-versions/ 가 PDF 를 보관하는 것과 같은 이유로, 빌드 환경이
               없는 사람도 바로 제출·시연할 수 있어야 한다.
```

**내용 수정은 `index.html` 에서 하고 `./build.sh` 를 다시 돌린다.**
`dist/index.html` 을 직접 고치면 다음 빌드에 지워진다.

## 배포본 만들기

```sh
./build.sh              # 폰트까지 묻는다(기본, 약 530KB)
./build.sh --no-fonts   # 링크만 유지. 가볍지만 볼 때 인터넷이 필요하다
```

`dist/index.html` 한 파일이면 끝이다. 스크립트도 외부 요청도 없다.

**폰트를 묻는 이유:** Google Fonts 가 막히면 조용히 대체 글꼴로 렌더된다 —
발표장에서 그걸 알아챌 방법이 없다. 한글은 원래 시스템 글꼴로 떨어지므로
(IBM Plex 에 한글이 없다) latin 서브셋 16개만 가져온다.

## 올리는 방법 (Vercel 안 씀)

어느 쪽이든 **`dist/` 폴더 통째로** 올리면 된다. 빌드 설정이 필요 없다.

| 방법 | 절차 |
|---|---|
| **그냥 파일로** | `dist/index.html` 더블클릭. 인터넷 없이도 그대로 나온다. USB·메일 첨부·제출용 |
| **GitHub Pages** | 저장소에 `dist/` 내용을 올리고 Settings → Pages → Branch 선택. `.nojekyll` 이 들어 있어 Jekyll 이 건드리지 않는다 |
| **Netlify / Cloudflare Pages** | 대시보드에 `dist/` 폴더를 끌어다 놓는다. 빌드 명령 없음, 출력 디렉터리만 지정 |
| **학교 웹서버 / 사내 호스팅** | `dist/` 를 FTP·scp 로 복사 |

`404.html` 도 같은 내용으로 넣어뒀다 — 호스트가 오타 주소에 자기 404 페이지를
띄우는 대신 이 페이지를 보여준다.

## 확인 (판을 고쳤으면 매번)

```sh
./build.sh
docker run --rm -v "$PWD/dist:/work" tpot/html2pdf:local \
  chromium --headless --no-sandbox --disable-gpu --disable-dev-shm-usage \
    --virtual-time-budget=12000 --window-size=1280,5600 --hide-scrollbars \
    --screenshot=/work/_check.png /work/index.html
# 한글이 깨지지 않았는지, 팀 섹션이 4칸으로 나오는지 눈으로 본다
rm dist/_check.png
```

## 팀 표기

이름 카드(이현·김동현·홍영재·이재민)와 `맡은 일` 목록은 **일부러 붙여놓지 않았다.**
역할 4칸은 코드를 보고 추정한 구분이고 담당자 기록이 어디에도 없다. 매핑이
확정되면 `.scope` 목록을 개인별로 바꾼다. 경위는 작업 로그 §32.
