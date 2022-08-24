package com.userfront.repository;

import com.userfront.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {

    User readByEmail(String email);

}
