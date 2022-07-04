package com.mycode.springsecurity.web;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

@RestController
public class HelloController {

    @RequestMapping("/hello/root")
    public Object helloRoot(HttpServletRequest request){
        // Cookie[] cookies = request.getCookies();
        // System.out.println(cookies[0].getValue());
        return "Hello root!";
    }

    @RequestMapping("/hello/world")
    public Object helloWorld(){
        return "Hello World!";
    }

    @RequestMapping("/hello/admin")
    public Object helloAdmin(){
        return "Hello admin!";
    }

    @RequestMapping("/check")
    public Object loginCheck(Principal principal) {
        String username = principal.getName();

        Map<String, Object> map = new HashMap<>();
        map.put("code", 200);
        map.put("success", true);
        map.put("user", username);
        return map;
    }
}
