package com.example.fido2.adapter.out.persistence.repository;

import com.example.fido2.adapter.out.persistence.entity.RpConfigEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RpConfigJpaRepository extends JpaRepository<RpConfigEntity, Long> {

    Optional<RpConfigEntity> findByRpIdAndActiveTrue(String rpId);
}
