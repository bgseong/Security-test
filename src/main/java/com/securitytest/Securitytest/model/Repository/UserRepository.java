package com.securitytest.Securitytest.model.Repository;

import com.securitytest.Securitytest.model.Entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface UserRepository extends JpaRepository<User,Long> {
    User findByEmail(String email);

    User findByUserName(String userName);
}
