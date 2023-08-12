package com.example.springsecuritydemo.mapper;

import com.example.springsecuritydemo.po.Role;
import com.example.springsecuritydemo.po.User;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;

@Mapper
public interface UserMapper {
    //根据用户名查询用户
    User loadUserByUsername(String username);
  	
  	//根据用户id查询角色
  	List<Role> getRolesByUid(Long uid);

    Integer updatePassword(@Param("username") String username, @Param("password") String password);
}