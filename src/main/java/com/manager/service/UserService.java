package com.manager.service;

import com.manager.model.User;

public interface UserService {

    public User findUserByEmail(String email);

    public void saveUser(User user);

}
