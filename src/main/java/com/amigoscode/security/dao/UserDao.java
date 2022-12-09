package com.amigoscode.security.dao;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Repository;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

// dao data access object
@Repository
public class UserDao {

    private final static List<UserDetails> APPLICATION_USER = Arrays.asList(
            new User("j.bedrich@eos-ts.com", "123", Collections.singleton(new SimpleGrantedAuthority("ROLE_USER"))), //username, password, role
            new User("t.reiss@eos-ts.com", "123", Collections.singleton(new SimpleGrantedAuthority("ROLE_USER"))),
            new User("d.auer@eos-ts.com", "999", Collections.singleton(new SimpleGrantedAuthority("ROLE_ADMIN")))

    );

    public UserDetails findUserByEmail(String email){
        return APPLICATION_USER
                .stream()
                .filter(u -> u.getUsername().equals(email))
                .findFirst()
                .orElseThrow(() -> new UsernameNotFoundException("Email was not found!"));
    }
}
