package com.capstone.honeypot.service;

import com.capstone.honeypot.domain.Project;
import com.capstone.honeypot.domain.User;
import com.capstone.honeypot.dto.ProjectCreateRequest;
import com.capstone.honeypot.dto.ProjectResponse;
import com.capstone.honeypot.repository.ProjectRepository;
import com.capstone.honeypot.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class ProjectService {

    private final ProjectRepository projectRepository;
    private final UserRepository userRepository;

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

    public List<ProjectResponse> findAll() {
        return projectRepository.findAll()
                .stream()
                .map(ProjectResponse::new)
                .toList();
    }

    public ProjectResponse findById(Long id) {
        Project project = projectRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("해당 프로젝트가 없습니다. id=" + id));
        return new ProjectResponse(project);
    }

    public void delete(Long id) {
        projectRepository.deleteById(id);
    }

    public List<ProjectResponse> findMyProjects(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("해당 사용자가 없습니다. email=" + email));

        return projectRepository.findByUserId(user.getId())
                .stream()
                .map(ProjectResponse::new)
                .toList();
    }
}