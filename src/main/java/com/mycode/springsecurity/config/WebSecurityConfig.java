package com.mycode.springsecurity.config;

import com.mycode.springsecurity.config.handler.CustomizeAbstractSecurityInterceptor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;

import javax.annotation.Resource;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Resource
    private UserDetailsService userDetailsService;
    @Resource
    private AuthenticationEntryPoint authenticationEntryPoint;
    @Resource
    private AccessDeniedHandler accessDeniedHandler;
    @Resource
    private AuthenticationSuccessHandler authenticationSuccessHandler;
    @Resource
    private AuthenticationFailureHandler authenticationFailureHandler;
    @Resource
    private LogoutSuccessHandler logoutSuccessHandler;
    @Resource
    private SessionInformationExpiredStrategy sessionInformationExpiredStrategy;
    @Resource
    private AccessDecisionManager accessDecisionManager;
    @Resource
    private FilterInvocationSecurityMetadataSource securityMetadataSource;
    @Resource
    private CustomizeAbstractSecurityInterceptor  securityInterceptor;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // http.csrf().disable();
        http.cors().and().csrf().disable();
        // super.configure(http);
        http.authorizeRequests()
                // .antMatchers("/hello/world").permitAll()
                // .antMatchers("/hello/root").hasAnyRole("root")
                // .anyRequest().authenticated()
                .withObjectPostProcessor(new ObjectPostProcessor<FilterSecurityInterceptor>() {
                    @Override
                    public <O extends FilterSecurityInterceptor> O postProcess(O o) {
                        o.setAccessDecisionManager(accessDecisionManager);//决策管理器
                        o.setSecurityMetadataSource(securityMetadataSource);//安全元数据源
                        return o;
                    }
                })
                .and().formLogin().permitAll()
                .successHandler(authenticationSuccessHandler)
                .failureHandler(authenticationFailureHandler)
                .and().logout().permitAll()
                .logoutSuccessHandler(logoutSuccessHandler).deleteCookies("JSESSIONID")
                .and().exceptionHandling()
                .authenticationEntryPoint(authenticationEntryPoint)
                .accessDeniedHandler(accessDeniedHandler)
                .and().sessionManagement()
                .maximumSessions(1).expiredSessionStrategy(sessionInformationExpiredStrategy)
                ;
        http.addFilterBefore(securityInterceptor, FilterSecurityInterceptor.class);
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}
