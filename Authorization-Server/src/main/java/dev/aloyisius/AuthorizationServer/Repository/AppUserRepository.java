package dev.aloyisius.AuthorizationServer.Repository;

import dev.aloyisius.AuthorizationServer.Entity.AppUsers;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AppUserRepository extends JpaRepository<AppUsers, Long> {
    Optional<AppUsers> findByEmail(String email);
}
