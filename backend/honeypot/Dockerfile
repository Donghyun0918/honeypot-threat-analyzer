# capstone backend (Spring Boot 3.4.0, Java 17) — threat-console 통합본
# 멀티스테이지: gradle 빌드 → JRE 실행.
FROM eclipse-temurin:17-jdk-alpine AS builder
WORKDIR /app

# 의존성 캐싱: 빌드 스크립트 + wrapper 먼저 복사
COPY gradlew settings.gradle build.gradle ./
COPY gradle gradle/
RUN chmod +x gradlew && ./gradlew dependencies --no-daemon -q || true

COPY src src/
RUN ./gradlew bootJar --no-daemon -x test -q

FROM eclipse-temurin:17-jre-alpine
WORKDIR /app
# root 로 돌리지 않는다 — 웹 요청을 직접 받는 컨테이너다.
RUN addgroup -S app && adduser -S -G app app
COPY --chown=app:app --from=builder /app/build/libs/*.jar app.jar
USER app
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
