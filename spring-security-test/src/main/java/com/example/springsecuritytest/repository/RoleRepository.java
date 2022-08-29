package com.example.springsecuritytest.repository;

import com.example.springsecuritytest.entity.ERole;
import com.example.springsecuritytest.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}
