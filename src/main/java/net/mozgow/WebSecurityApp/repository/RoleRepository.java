package net.mozgow.WebSecurityApp.repository;

import net.mozgow.WebSecurityApp.models.ERole;
import net.mozgow.WebSecurityApp.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}
