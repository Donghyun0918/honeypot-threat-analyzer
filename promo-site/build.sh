#!/bin/sh
# 소개 웹사이트 배포본 생성 — dist/index.html 한 파일.
#
# index.html 은 <title> 로 시작하는 **조각**이다(doctype·html·head·body 없음).
# Artifact 호스트가 감싸주던 것이라, 그대로 정적 호스팅에 올리면 charset 이 없어
# 한글이 깨진다. 이 스크립트가 제대로 된 문서로 감싼다.
#
# 폰트도 함께 묻는다. 발표장에서 인터넷이 막히면 Google Fonts 가 조용히 실패해
# 대체 글꼴로 렌더된다 — 그 자리에서 알아챌 방법이 없다. 묻어두면 그럴 일이 없다.
# 한글은 원래 시스템 글꼴로 떨어지므로(IBM Plex 에 한글이 없다) latin 서브셋만
# 가져온다.
#
#   ./build.sh            폰트 임베드(기본)
#   ./build.sh --no-fonts 링크만 유지(빠름, 인터넷 필요)
set -e
cd "$(dirname "$0")"

EMBED=1
[ "$1" = "--no-fonts" ] && EMBED=0

mkdir -p dist
python3 - "$EMBED" <<'PY'
import base64, io, re, sys, urllib.request

EMBED = sys.argv[1] == "1"
SRC = "index.html"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")  # woff2 를 받으려면 필요

frag = io.open(SRC, encoding="utf-8").read()

# 조각에서 <title> 과 폰트 <link> 를 떼어내 head 로 옮긴다.
m = re.search(r"<title>(.*?)</title>", frag)
title = m.group(1) if m else "정사평"
frag = frag.replace(m.group(0), "", 1) if m else frag

links = re.findall(r'<link[^>]*>', frag)
css_url = next((re.search(r'href="([^"]+)"', l).group(1)
                for l in links if "css2?" in l), None)
for l in links:
    frag = frag.replace(l, "", 1)
frag = frag.strip()

def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    return urllib.request.urlopen(req, timeout=30).read()

font_css = ""
if EMBED and css_url:
    css = fetch(css_url).decode("utf-8")
    # Google 은 서브셋마다 /* latin */ 같은 주석을 앞에 붙인다.
    # 한글은 시스템 글꼴로 떨어지므로 latin 계열만 남긴다 — 키릴·그리스까지
    # 다 묻으면 파일이 몇 배가 된다.
    blocks = re.split(r"(?=/\*\s*[a-z-]+\s*\*/)", css)
    keep, n = [], 0
    for b in blocks:
        tag = re.match(r"/\*\s*([a-z-]+)\s*\*/", b.strip())
        if not tag or tag.group(1) not in ("latin", "latin-ext"):
            continue
        def sub(mm):
            global n
            data = fetch(mm.group(1))
            n_local = base64.b64encode(data).decode("ascii")
            return "url(data:font/woff2;base64,%s)" % n_local
        keep.append(re.sub(r"url\((https://fonts\.gstatic\.com/[^)]+)\)", sub, b))
        n += 1
    font_css = "".join(keep)
    print("폰트 %d 서브셋 임베드" % n)
    head_fonts = "<style>%s</style>" % font_css
elif css_url:
    head_fonts = ('<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>'
                  '<link rel="stylesheet" href="%s">' % css_url)
else:
    head_fonts = ""

DESC = ("허니팟이 받아낸 공격 로그 100만 건을 규칙·ML 교차검증으로 분류하고 "
        "고위험만 골라 한국어로 해설하는 시스템. 캡스톤 졸업작품(팀 정사평).")

# 아이콘: 외부 파일을 만들면 배포 대상이 두 개가 된다. SVG 를 data URI 로 묻어
# 단일 파일을 유지한다.
ICON = ('data:image/svg+xml,'
        "%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E"
        "%3Crect width='32' height='32' rx='7' fill='%230F6B78'/%3E"
        "%3Cpath d='M16 6l8 3.6v6.2c0 5-3.4 8.6-8 10.2-4.6-1.6-8-5.2-8-10.2V9.6z' "
        "fill='none' stroke='%23fff' stroke-width='2.2' stroke-linejoin='round'/%3E"
        "%3C/svg%3E")

doc = """<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>{title}</title>
<meta name="description" content="{desc}">
<meta property="og:type" content="website">
<meta property="og:title" content="{title}">
<meta property="og:description" content="{desc}">
<meta property="og:locale" content="ko_KR">
<link rel="icon" href="{icon}">
{fonts}
<style>
  /* Artifact 호스트가 넣어주던 최소 리셋. 정적 호스팅엔 없으므로 직접 넣는다. */
  html {{ -webkit-text-size-adjust: 100%; }}
  img {{ max-width: 100%; }}
  [hidden] {{ display: none !important; }}
</style>
</head>
<body>
{body}
</body>
</html>
""".format(title=title, desc=DESC, icon=ICON, fonts=head_fonts, body=frag)

io.open("dist/index.html", "w", encoding="utf-8").write(doc)
print("dist/index.html 생성 — %.0f KB" % (len(doc.encode("utf-8")) / 1024))
PY

# 정적 호스트가 404 를 자체 페이지로 돌리지 않도록 같은 문서를 둔다.
cp dist/index.html dist/404.html
# GitHub Pages 가 Jekyll 로 처리하려 들면 _ 로 시작하는 것들이 사라진다.
: > dist/.nojekyll

echo "dist/ 준비 완료:"
ls -la dist/
