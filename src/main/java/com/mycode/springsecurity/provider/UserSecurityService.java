package com.mycode.springsecurity.provider;

import com.mycode.springsecurity.entity.SysUser;
import com.mycode.springsecurity.mapper.RoleMapper;
import com.mycode.springsecurity.mapper.SysUserMapper;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.ArrayList;
import java.util.List;

@Service
public class UserSecurityService implements UserDetailsService {

    @Resource
    private SysUserMapper sysUserMapper;
    @Resource
    RoleMapper roleMapper;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if(username == null){
            throw new UsernameNotFoundException("name is null!");
        }

        SysUser sysUser =sysUserMapper.selectByAccount(username);
        if(sysUser == null){
            throw new UsernameNotFoundException("the account: " + username + " not found!");
        }

        List<String> roles = roleMapper.selectRolesByUserId(sysUser.getId());

        if(roles.size() == 0){
            throw new UsernameNotFoundException("no role records found!");
        }

        List<GrantedAuthority> authorities = new ArrayList<>();
        roles.forEach(r -> authorities.add(new SimpleGrantedAuthority("ROLE_" + r)));

        User user = new User(username, sysUser.getPassword(), sysUser.getEnabled(),
                sysUser.getNotExpired(), sysUser.getCredentialsNotExpired(), sysUser.getAccountNotLocked(),
                authorities);

        return user;
    }

}
