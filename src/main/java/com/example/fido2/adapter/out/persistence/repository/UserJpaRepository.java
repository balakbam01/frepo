package com.example.fido2.adapter.out.persistence.repository;

import com.example.fido2.adapter.out.persistence.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

/** Spring Data JPA repository for {@link UserEntity}. */
public interface UserJpaRepository extends JpaRepository<UserEntity, Long> {

    Optional<UserEntity> findByUsername(String username);

    Optional<UserEntity> findByUserId(String userId);

    boolean existsByUsername(String username);
}
