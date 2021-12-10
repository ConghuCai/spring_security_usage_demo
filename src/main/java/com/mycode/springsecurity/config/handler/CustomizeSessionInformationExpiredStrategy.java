package com.mycode.springsecurity.config.handler;

import com.alibaba.fastjson.JSON;
import org.springframework.security.web.session.SessionInformationExpiredEvent;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Component
public class CustomizeSessionInformationExpiredStrategy implements SessionInformationExpiredStrategy {
    @Override
    public void onExpiredSessionDetected(SessionInformationExpiredEvent event) throws IOException, ServletException {
        Map<String, Object> map = new HashMap<>();
        map.put("code", 305);
        map.put("msg", "账号已下线");
        map.put("success", false);
        String json = JSON.toJSONString(map);

        HttpServletResponse response = event.getResponse();
        response.setContentType("text/json;charset=utf-8");
        response.getWriter().write(json);
    }
}
