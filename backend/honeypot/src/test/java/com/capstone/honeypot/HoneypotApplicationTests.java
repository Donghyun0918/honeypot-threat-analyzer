package com.capstone.honeypot;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * Spring Initializr 가 만들어준 기본 테스트.
 *
 * <p><b>비활성이다.</b> 전체 컨텍스트를 올리려면 PostgreSQL 과 Elasticsearch 가
 * 실제로 떠 있어야 하는데, 그러면 "테스트를 돌리려면 스택부터 띄워야 한다" 가
 * 되어 아무도 돌리지 않는다. 나머지 테스트는 준비물 없이 돈다.
 *
 * <p>덧붙여 이 테스트는 {@code build.gradle} 에 {@code useJUnitPlatform()} 이
 * 없어서 <b>여태 한 번도 실행된 적이 없었다</b> — Gradle 이 JUnit 4 러너로
 * 테스트를 하나도 못 찾고도 BUILD SUCCESSFUL 을 냈다. 그 설정을 넣으면서
 * 드러났고, 스택을 띄운 상태에서 돌리려면 아래 애노테이션을 지우면 된다.
 */
@Disabled("전체 컨텍스트 로드에는 PostgreSQL·Elasticsearch 가 필요하다")
@SpringBootTest
class HoneypotApplicationTests {

    @Test
    void contextLoads() {
    }

}
