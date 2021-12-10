package com.mycode.springsecurity;

import com.mycode.springsecurity.entity.Role;
import com.mycode.springsecurity.entity.SysUser;
import com.mycode.springsecurity.mapper.RoleMapper;
import com.mycode.springsecurity.mapper.SysUserMapper;
import com.mycode.springsecurity.provider.UserSecurityService;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.annotation.Resource;
import java.util.List;

@SpringBootTest
class ApplicationTests {

    @Test
    void contextLoads() {
    }

    @Resource
    SysUserMapper sysUserMapper;

    @Test
    void SysUserMapperTest(){
        SysUser user = sysUserMapper.selectByPrimaryKey(1);
        System.out.println(user.getUserName());

    }

    @Resource
    RoleMapper roleMapper;

    @Test
    void roleMapperTest(){
        List<String> roles = roleMapper.selectRolesByUserId(1);
        roles.forEach(r -> System.out.println(r));
    }

    @Resource
    UserSecurityService userSecurityService;
    @Test
    void userSecurityServiceTest(){
        User user = (User) userSecurityService.loadUserByUsername("1001");
        System.out.println(user.getUsername() + " " + user.getPassword());
    }

}
