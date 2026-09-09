# capstone backend (Spring Boot 3.4.0, Java 17) — threat-console 통합본
# 멀티스테이지: gradle 빌드 → JRE 실행. profiling-service Dockerfile 패턴 적응.
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
COPY --from=builder /app/build/libs/*.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
