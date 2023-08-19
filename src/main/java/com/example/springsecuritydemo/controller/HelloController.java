package com.example.springsecuritydemo.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping()
public class HelloController {

    /**
     *
     *  admin   role_admin role_user   /admin/**    /user/**    /guest/**
     *  user    role_user              /user/**     /guest/**
     *  brl     role_guest             /guest/**
     *
     */



    @GetMapping("/admin/hello")
    public String admin() {
        return "hello admin";
    }

    @GetMapping("/user/hello")
    public String user() {
        return "hello user";
    }

    @GetMapping("/guest/hello")
    public String guest() {
        return "hello guest";
    }

    @GetMapping("/hello")
    public String hello() {
        return "hello";
    }
}
