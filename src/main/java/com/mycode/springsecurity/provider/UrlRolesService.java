package com.mycode.springsecurity.provider;

import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class UrlRolesService {

    public List<String> getUrlRoles(String url){
        if(url.charAt(url.length()-1) == '/'){
            url = url.substring(0, url.length()-1);
        }

        List<String> roles = new ArrayList<>();
        if(url.equals("/hello/root")){
            roles.add("root");
            return roles;
        } else if(url.equals("/hello/admin")){
            roles.add("admin");
            return roles;
        } else if(url.equals("/check")){
            // roles.add("admin");
            roles.add("root");
            return roles;
        }

        return null;
    }

}
