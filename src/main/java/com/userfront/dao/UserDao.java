package com.userfront.dao;

import com.userfront.domain.User;
import org.springframework.data.repository.CrudRepository;

import java.util.List;


public interface UserDao extends CrudRepository<User, Long> {
    //public interface UserDao extends CrudRepository<User, Long> {

	User findByUsername(String username);
    User findByEmail(String email);

    User save(User user); //remove?
    List<User> findAll();
}
