package com.userfront;

import com.userfront.dao.UserDao;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@ExtendWith(SpringExtension.class)
@SpringBootTest
public class UserFrontApplicationTests {

	@Autowired
	private TestEntityManager entityManager;
	@Autowired
	private UserDao userDao;
	@Test
	public void contextLoads() {
	}

}
