package com.example.springsecuritydemo.mapper;

import com.example.springsecuritydemo.po.Menu;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

@Mapper
public interface MenuMapper {
    List<Menu> getAllMenu();
}