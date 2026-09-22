package com.capstone.honeypot.service;

import com.capstone.honeypot.domain.AssetProfile;
import com.capstone.honeypot.domain.User;
import com.capstone.honeypot.repository.AssetProfileRepository;
import com.capstone.honeypot.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 자산 포트 목록의 격리·상한 회귀 테스트.
 *
 * <p>이 목록은 <b>"어느 조직이 어떤 포트를 열어놨는가"</b> 다. 여러 사람이 한
 * 센서를 공유하는 형태에서 남의 것이 보이면 그대로 사고다. 조회가 언제나
 * 이메일로 걸리는지, 상한이 지켜지는지를 못 박는다.
 *
 * <p>Mockito 를 쓰지 않는다. 이 컨테이너에서 MockMaker 플러그인이 초기화되지
 * 않아 테스트가 대상이 아니라 자기 도구 때문에 실패했다. 리포지토리는 인터페이스
 * 이므로 {@link Proxy} 로 필요한 메서드만 처리하는 가짜를 만들면 충분하고,
 * 준비물 없이 도는 사이드카 테스트와도 결이 맞는다.
 */
class AssetProfileServiceTest {

    private AssetProfileService service;
    private Map<String, AssetProfile> 저장소;
    private List<String> 조회한이메일;
    private Set<String> 있는사용자;

    /** 인터페이스의 메서드를 이름으로 갈라 처리하는 가짜. 나머지는 쓰면 터진다. */
    @SuppressWarnings("unchecked")
    private static <T> T 가짜(Class<T> 형, Map<String, java.util.function.Function<Object[], Object>> 동작) {
        return (T) Proxy.newProxyInstance(형.getClassLoader(), new Class<?>[]{형},
                (proxy, method, args) -> {
                    var f = 동작.get(method.getName());
                    if (f == null) {
                        throw new UnsupportedOperationException(
                                "테스트가 예상하지 않은 호출: " + 형.getSimpleName() + "." + method.getName());
                    }
                    return f.apply(args == null ? new Object[0] : args);
                });
    }

    @BeforeEach
    void 준비() {
        저장소 = new HashMap<>();
        조회한이메일 = new ArrayList<>();
        있는사용자 = new HashSet<>(List.of("a@x.test", "b@x.test"));

        var users = 가짜(UserRepository.class, Map.of(
                "findByEmail", args -> {
                    String email = (String) args[0];
                    if (!있는사용자.contains(email)) return Optional.empty();
                    User u = new User();
                    u.setEmail(email);
                    return Optional.of(u);
                }));

        var assets = 가짜(AssetProfileRepository.class, Map.of(
                "findByUserEmail", args -> {
                    조회한이메일.add((String) args[0]);
                    return Optional.ofNullable(저장소.get(args[0]));
                },
                "save", args -> {
                    AssetProfile p = (AssetProfile) args[0];
                    저장소.put(p.getUser().getEmail(), p);
                    return p;
                }));

        service = new AssetProfileService(assets, users);
    }

    @Test
    void 저장한_원문이_그대로_돌아온다() {
        // 포트만 뽑아 저장하면 "웹서버 80, 443" 의 맥락이 사라져 다시 열었을 때
        // 자기가 뭘 적었는지 알아볼 수 없다.
        String 입력 = "웹서버 80, 443\n파일서버 445";
        service.저장("a@x.test", 입력);
        assertEquals(입력, service.읽기("a@x.test"));
    }

    @Test
    void 다른_사용자의_목록은_보이지_않는다() {
        service.저장("a@x.test", "A사 웹 80");
        service.저장("b@x.test", "B사 DB 3306");
        assertEquals("A사 웹 80", service.읽기("a@x.test"));
        assertEquals("B사 DB 3306", service.읽기("b@x.test"));
    }

    @Test
    void 목록이_없으면_빈_문자열이지_예외가_아니다() {
        // 처음 들어온 사용자에게 오류 화면을 보여줄 이유가 없다.
        assertEquals("", service.읽기("a@x.test"));
    }

    @Test
    void 조회는_언제나_이메일로_걸린다() {
        service.읽기("a@x.test");
        assertEquals(List.of("a@x.test"), 조회한이메일);
    }

    @Test
    void 지나치게_긴_입력은_거부한다() {
        var e = assertThrows(IllegalArgumentException.class,
                () -> service.저장("a@x.test", "8".repeat(4001)));
        assertTrue(e.getMessage().contains("4000"), e.getMessage());
    }

    @Test
    void 상한_경계값은_통과한다() {
        String 딱맞음 = "8".repeat(4000);
        assertDoesNotThrow(() -> service.저장("a@x.test", 딱맞음));
        assertEquals(딱맞음, service.읽기("a@x.test"));
    }

    @Test
    void null_은_빈_문자열로_저장된다() {
        service.저장("a@x.test", null);
        assertEquals("", service.읽기("a@x.test"));
    }

    @Test
    void 없는_사용자로는_저장할_수_없다() {
        assertThrows(IllegalArgumentException.class, () -> service.저장("유령@x.test", "80"));
    }

    @Test
    void 두_번_저장하면_덮어쓰지_행이_늘지_않는다() {
        service.저장("a@x.test", "80");
        service.저장("a@x.test", "443");
        assertEquals("443", service.읽기("a@x.test"));
        assertEquals(1, 저장소.size());
    }
}
