package com.capstone.honeypot.service;

import com.capstone.honeypot.domain.Project;
import com.capstone.honeypot.domain.User;
import com.capstone.honeypot.dto.ProjectCreateRequest;
import com.capstone.honeypot.dto.ProjectResponse;
import com.capstone.honeypot.repository.ProjectRepository;
import com.capstone.honeypot.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * 프로젝트 조회·생성.
 *
 * <p>읽기 메서드에 {@code @Transactional(readOnly = true)} 가 붙어 있는 이유:
 * {@link com.capstone.honeypot.dto.ProjectResponse} 가
 * {@code project.getUser().getEmail()} 을 읽는데 {@code Project.user} 는
 * {@code FetchType.LAZY} 다. 트랜잭션 경계가 없으면 리포지토리 호출이 끝나는 순간
 * 엔티티가 분리되어 DTO 를 만들 때 {@code LazyInitializationException} 이 난다.
 *
 * <p>그전까지는 {@code spring.jpa.open-in-view} 가 기본 활성이라 영속성 컨텍스트가
 * 요청 끝까지 열려 있어서 <b>우연히</b> 동작했다. 그 설정을 끄면서(REST API 에는
 * 불필요하고 DB 커넥션을 요청 내내 붙든다) 의존하던 곳을 제 경계로 옮긴다.
 */
@Service
@RequiredArgsConstructor
public class ProjectService {

    private final ProjectRepository projectRepository;
    private final UserRepository userRepository;

    @Transactional
    public ProjectResponse create(ProjectCreateRequest request, String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("해당 사용자가 없습니다. email=" + email));

        Project project = new Project();
        project.setName(request.getName());
        project.setDescription(request.getDescription());
        project.setUser(user);

        Project savedProject = projectRepository.save(project);
        return new ProjectResponse(savedProject);
    }

    @Transactional(readOnly = true)
    public List<ProjectResponse> findAll() {
        return projectRepository.findAll()
                .stream()
                .map(ProjectResponse::new)
                .toList();
    }

    @Transactional(readOnly = true)
    public ProjectResponse findById(Long id) {
        Project project = projectRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("해당 프로젝트가 없습니다. id=" + id));
        return new ProjectResponse(project);
    }

    @Transactional
    public void delete(Long id) {
        projectRepository.deleteById(id);
    }

    @Transactional(readOnly = true)
    public List<ProjectResponse> findMyProjects(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("해당 사용자가 없습니다. email=" + email));

        return projectRepository.findByUserId(user.getId())
                .stream()
                .map(ProjectResponse::new)
                .toList();
    }
}