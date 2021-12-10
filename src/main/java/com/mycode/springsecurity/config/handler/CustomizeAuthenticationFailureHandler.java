package com.mycode.springsecurity.config.handler;

import com.alibaba.fastjson.JSON;
import org.springframework.security.authentication.*;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Component
public class CustomizeAuthenticationFailureHandler implements AuthenticationFailureHandler {
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException, ServletException {
        String msg;
        if (e instanceof AccountExpiredException) {
            //账号过期
            msg = "账号过期";
        } else if (e instanceof BadCredentialsException) {
            //密码错误
            msg = "密码错误";
        } else if (e instanceof CredentialsExpiredException) {
            //密码过期
            msg = "密码过期";
        } else if (e instanceof DisabledException) {
            //账号不可用
            msg = "账号不可用";
        } else if (e instanceof LockedException) {
            //账号锁定
            msg = "账号锁定";
        } else if (e instanceof InternalAuthenticationServiceException) {
            //用户不存在
            msg = "用户不存在";
        }else{
            //其他错误
            msg = "其他错误";
        }

        Map<String, Object> map = new HashMap<>();
        map.put("code", 198);
        map.put("msg", msg);
        map.put("success", false);
        String json = JSON.toJSONString(map);

        response.setContentType("text/json;charset=utf-8");
        response.getWriter().write(json);
    }
}
