package com.example.springsecuritydemo.service;

import com.example.springsecuritydemo.mapper.MenuMapper;
import com.example.springsecuritydemo.po.Menu;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class MenuService {
    private final MenuMapper menuMapper;

    @Autowired
    public MenuService(MenuMapper menuMapper) {
        this.menuMapper = menuMapper;
    }

    public List<Menu> getAllMenu() {
        return menuMapper.getAllMenu();
    }
}