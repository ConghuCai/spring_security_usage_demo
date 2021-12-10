package com.mycode.springsecurity.config.handler;

import com.mycode.springsecurity.provider.UrlRolesService;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;
import java.util.Collection;
import java.util.List;

/**
 * 拦截到当前的请求，并根据请求路径从数据库中查出当前资源路径需要哪些权限才能访问
 */
@Component
public class CustomizeFilterInvocationSecurityMetadataSource implements FilterInvocationSecurityMetadataSource {

    @Resource
    private UrlRolesService urlRolesService;

    @Override
    public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {
        //请求地址
        String requestUrl = ((FilterInvocation)object).getRequestUrl();

        //查询url允许访问的role
        List<String> roles = urlRolesService.getUrlRoles(requestUrl);

        if(roles == null){
            return null;
        }

        String[] attributes = new String[roles.size()];
        int i=0;
        for(String role : roles){
            attributes[i++] = role;
        }

        return SecurityConfig.createList(attributes);

    }

    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        return null;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return true;
    }
}
