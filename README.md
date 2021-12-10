# SpringSecurity+SpringBoot+前后端分离的权限验证和管理的实现方法

## 0.本文目标

使用SpringSecurity框架进行访问用户的身份验证和权限鉴定，而且做成前后端分离的模式，即后端数据库没有界面，只返回Json作为处理结果。

## 1.SpringSecurity的作用

SpringSecurity提供了一个权限的验证管理的快速搭建工具。

以Web开发为例，使用SpringSecurity框架后，

* 可以对前端发来的url请求进行拦截，从而验证用户的权限是否允许该用户进行此请求。
* 提供了登录和登出的接口，当用户向接口传入账号密码信息后，框架会根据已知的用户列表验证账号密码，并读取该用户的权限，标记该用户的Session对象；登出时，也会销毁用户的JSessionID信息。
* 这个用户列表既可以写在代码里面（基于内存访问），也可以通过Dao层和Service层从数据库里获取（基于JDBC的访问）。
* 支持用户和权限直接对应，也支持RBAC（基于角色的控制管理），即用户和角色对应，角色再对应权限。

## 2.SpringSecurity的原理

SpringSecurity 采用的是责任链的设计模式，它有一条很长的过滤器链。

原理图：

![Security原理图.jpg](https://s2.loli.net/2021/12/09/ZNc3dBzp2UHfiMa.jpg)

流程：

1. 客户端发起一个请求，进入 Security 过滤器链。
2. 当到 **LogoutFilter** 的时候判断是否是登出路径，如果是登出路径则到 logoutHandler ，如果登出成功则到 **logoutSuccessHandler** 登出成功处理，如果登出失败则由 ExceptionTranslationFilter ；如果不是登出路径则直接进入下一个过滤器。
3. 当到 **UsernamePasswordAuthenticationFilter** 的时候判断是否为登录路径，如果是，则进入该过滤器进行登录操作，如果登录失败则到 **AuthenticationFailureHandler** 登录失败处理器处理，如果登录成功则到 **AuthenticationSuccessHandler** 登录成功处理器处理，如果不是登录请求则不进入该过滤器。
4. 当到 **FilterSecurityInterceptor** 的时候会拿到 url，根据 url 去找对应的鉴权管理器，鉴权管理器做鉴权工作，鉴权成功则到 Controller 层，否则到 **AccessDeniedHandler** 鉴权失败处理器处理。

因此原始的Security框架是当陌生用户访问某个url时，会自动返会登录form要求用户提供登录信息，登陆后会记录用户的SessionID。之后再根据用户访问的这个url所需要的权限和用户所具有的权限进行比对（即：鉴权），如果成功则执行url的Controller，失败则返回403Forbidden。

而我们的目标是前后端分离，后端只需要返回Json即可，因此我们需要使用框架提供的多个接口，自定义验证和鉴权过程。下面细说。

## 3.RBAC的Dao层设计

**RBAC即基于角色的访问控制**。Role代表着**权限的集合**，一个用户对应着多个role，每个role对应着多种权限，权限对应着多种url资源。Security框架支持基于JDBC的RBAC。**JDBC的访问控制可以将这些数据写入到数据库中进行持久化**，代码不写死，灵活性也更高。

因此数据库中设计表，主表部分至少包括User、Role、Permission、Path四个表，多对多的话涉及7个表的操作，这里稍稍简化一下，省去Permission和Path的对应关系，一个Role直接对应多个Url路径。即**User->Role->Path**。一共要有五个表。

````sql
-- ----------------------------
-- 请求路径表sys_path，包括所有需要权限才能访问的url地址，不需要权限的url就可以不用写进来了。
-- ----------------------------
DROP TABLE IF EXISTS `sys_path`;
CREATE TABLE `sys_path` (
  `id` int(11) NOT NULL AUTO_INCREMENT COMMENT '主键id',
  `url` varchar(64) NOT NULL COMMENT '请求路径',
  `description` varchar(128) DEFAULT NULL COMMENT '路径描述',
  PRIMARY KEY (`id`)
)

-- ----------------------------
-- 角色表sys_role，包含所有的系统角色，比如root、admin、normal这种。
-- ----------------------------
DROP TABLE IF EXISTS `sys_role`;
CREATE TABLE `sys_role` (
  `id` int(11) NOT NULL AUTO_INCREMENT COMMENT '主键id',
  `role_name` varchar(32) DEFAULT NULL COMMENT '角色名',
  `role_description` varchar(64) DEFAULT NULL COMMENT '角色说明',
  PRIMARY KEY (`id`)
)

-- ----------------------------
-- 用户表sys_user，包含的字段都是Security框架需要使用的。
-- 当然你也可以有选择性的添加这些字段，比如我只需要能锁定账号就可以了，那其他的过期、可用字段可以不添加。
-- ----------------------------
DROP TABLE IF EXISTS `sys_user`;
CREATE TABLE `sys_user` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `account` varchar(32) NOT NULL COMMENT '账号',
  `user_name` varchar(32) NOT NULL COMMENT '用户名',
  `password` varchar(64) DEFAULT NULL COMMENT '用户密码',
  `last_login_time` char(19) DEFAULT NULL COMMENT '上一次登录时间',
  `enabled` bit(1) DEFAULT b'1' COMMENT '账号是否可用。默认为1（可用）',
  `not_expired` bit(1) DEFAULT b'1' COMMENT '是否过期。默认为1（没有过期）',
  `account_not_locked` bit(1) DEFAULT b'1' COMMENT '账号是否锁定。默认为1（没有锁定）',
  `credentials_not_expired` bit(1) DEFAULT b'1' COMMENT '证书（密码）是否过期。默认为1（没有过期）',
  `create_time` char(19) DEFAULT NULL COMMENT '创建时间',
  `update_time` char(19) DEFAULT NULL COMMENT '修改时间',
  `create_user` int(11) DEFAULT NULL COMMENT '创建人',
  `update_user` int(11) DEFAULT NULL COMMENT '修改人',
  PRIMARY KEY (`id`)
)


-- ----------------------------
-- 三个表之间的关系表
-- ----------------------------

-- ----------------------------
-- Table structure for `sys_user_role_relation`
-- ----------------------------
DROP TABLE IF EXISTS `sys_user_role_relation`;
CREATE TABLE `sys_user_role_relation` (
  `id` int(11) NOT NULL AUTO_INCREMENT COMMENT '主键id',
  `user_id` int(11) DEFAULT NULL COMMENT '用户id',
  `role_id` int(11) DEFAULT NULL COMMENT '角色id',
  PRIMARY KEY (`id`)
) 

-- ----------------------------
-- Table structure for `sys_role_path_relation`
-- ----------------------------
DROP TABLE IF EXISTS `sys_role_path_relation`;
CREATE TABLE `sys_role_path_relation` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `role_id` int(11) DEFAULT NULL,
  `path_id` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`)
)

````

然后写Dao层和Service进行记录查询就可以了。Dao层使用JDBC、MyBatis都可以，反正只需要能够获取到数据库中的记录对象就行了。这里使用的是MyBatis，定义好Mapper接口，Xml里面写上Sql语句，入口主函数上面定义MapperScan注解，properties/yml配置里面配置数据源即可。

## 4.身份验证

思考一下：用户传入的用户名和密码，那么首先要做的是**去数据库里面找这个用户的权限信息**，之后再检查密码对不对、账号能不能使用、权限能不能对上等。

那么去数据库里面找这个用户其实就是一个简单的**实体+Dao+Service的经典流程**，Dao查user表，将结果封装成对象，Service返回这个对象给框架使用即可。

框架给我们提供了相关接口，实现这些接口就可以了。

### 4.1.UserDetail接口

Security框架将登入用户的信息封装到了**UserDetail**接口中，接口的内容包括用户名、密码、用户持有的权限、是否被锁定、是否过期等和权限相关的内容。

**UserDetail的实现类可以看作一个实体Bean。在Bean的基础上写Service类和Dao类即可。**

Security框架提供了自己的UserDetail实现类：**User**类，这里直接使用User类进行数据库用户表中记录的二次封装，当然我们也可以写一个自己的实现类。

### 4.2.UserDetailService接口

框架提供的UserDetail的Service接口，其中需要实现的方法是`UserDetails loadUserByUsername(String username)` ，即根据用户名username，调用Dao层查询数据库中的匹配的记录，并查询用户持有的权限信息，将用户的信息封装成UserDetails接口实现类返回即可。

````java
@Service
public class UserSecurityService implements UserDetailsService {

    @Resource
    private SysUserMapper sysUserMapper;	//SysUserMapper : sys_user表的Dao对象
    @Resource
    private RoleMapper roleMapper;	//sys_role表的Dao对象

    @Override
    //如果查无此人，抛出UsernameNotFoundException异常即可，框架会自己处理这个异常。
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if(username == null){
            throw new UsernameNotFoundException("name is null!");
        }

        SysUser sysUser =sysUserMapper.selectByAccount(username);	//查询用户的记录
        if(sysUser == null){
            throw new UsernameNotFoundException("the account: " + username + " not found!");
        }

        List<String> roles = roleMapper.selectRolesByUserId(sysUser.getId());	//查询用户所持有的Role信息

        if(roles.size() == 0){
            throw new UsernameNotFoundException("no role records found!");
        }

        List<GrantedAuthority> authorities = new ArrayList<>();
        //对于RBAC，role名称前必须加上"ROLE_"
        //框架是根据前缀是否有ROLE_来判断这是角色信息还是权限信息的。
        roles.forEach(r -> authorities.add(new SimpleGrantedAuthority("ROLE_" + r)));	
        
        //将查询到的信息封装到UserDetail的实现类：User里面。
        User user = new User(username, sysUser.getPassword(), sysUser.getEnabled(),
                sysUser.getNotExpired(), sysUser.getCredentialsNotExpired(), sysUser.getAccountNotLocked(),
                authorities);

        return user;
    }

}
````



## 5.鉴权

提供给框架UserDetailService接口的Bean后，框架现在可以拿数据库里的UserDetail对象来和用户传入的账号密码进行比对，从而完成身份验证了。我们完成了第一步！接下来就应该看一下，用户所需要访问的url需要哪些角色才可以访问？用户的角色能否满足要求？即进行鉴权工作。

框架提供了几个接口，实现这些接口来完成上述操作

### 5.1.FilterInvocationSecurityMetadataSource接口

FilterInvocationSecurityMetadataSource的核心方法是`Collection<ConfigAttribute> getAttributes(Object object)` ，这个方法定义了：针对一个请求的资源object，给出object需要的权限集合`Collection<ConfigAttribute>`。 

所以这个接口的本质就是一个Service接口，根据传入的url，用dao或者service对象查询role记录即可。

````java
/**
 * 拦截到当前的请求，并根据请求路径从数据库中查出当前资源路径需要哪些权限才能访问
 */
@Component
public class CustomizeFilterInvocationSecurityMetadataSource implements FilterInvocationSecurityMetadataSource {

    @Resource
    private UrlRolesService urlRolesService;

    @Override
    public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {
        //拿到请求地址
        String requestUrl = ((FilterInvocation)object).getRequestUrl();

        //查询url允许访问的role
        List<String> roles = urlRolesService.getUrlRoles(requestUrl);

        if(roles == null){
            return null;
        }
		
        //查询到的role集合是一个String的List，我们将其转为String的数组
        String[] attributes = new String[roles.size()];
        int i=0;
        for(String role : roles){
            attributes[i++] = role;
        }
		
        //使用SecurityConfig.createList方法，将数组中的String转为ConfigAttribute对象，并形成集合返回
        return SecurityConfig.createList(attributes);

    }

    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        return null;
    }

    @Override
    //开启
    public boolean supports(Class<?> clazz) {
        return true;
    }
}
````

### 5.2.AccessDecisionManager接口

通过实现FilterInvocationSecurityMetadataSource接口，我们可以根据url来查询可访问的角色集合了。

那么现在需要一个决定器，来根据用户持有角色，和url需要的角色，进行判断，判断用户是否可以访问这个url。这个工作，框架提供了AccessDecisionManager接口，我们可以自定义实现这个接口。

````java
@Component
public class CustomizeAccessDecisionManager implements AccessDecisionManager {
    @Override
    public void decide(Authentication authentication, Object object, Collection<ConfigAttribute> configAttributes) throws AccessDeniedException, InsufficientAuthenticationException {
        //configAttributes  访问需要的角色
        //authentication.getAuthorities()  用户的权限
        //两个其实都是集合，我们进行双层循环遍历一下，看有没有匹配上的就行了
        Iterator<ConfigAttribute> iterator = configAttributes.iterator();
        while (iterator.hasNext()) {
            ConfigAttribute ca = iterator.next();
            //当前请求需要的权限，因为我们做的是RBAC，所以拿到的权限名，前面要加ROLE_前缀
            String needRole = "ROLE_" + ca.getAttribute();

            //当前用户所具有的权限
            Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
            for (GrantedAuthority authority : authorities) {
                if (authority.getAuthority().equals(needRole)) {
                    //匹配上了就结束
                    return;
                }
            }
        }
        
        //没有匹配项，抛出AccessDeniedException异常
        throw new AccessDeniedException("权限不足!");
    }

    @Override
    //启用
    public boolean supports(ConfigAttribute attribute) {
        return true;
    }

    @Override
    //启用
    public boolean supports(Class<?> clazz) {
        return true;
    }
}
````

现在，我们就通过实现框架提供的接口，完成了用户的**身份验证**和**鉴权**的部分啦！

而且，我们的代码都是从数据库里获取的信息，**身份验证是根据用户名到数据库里查询**，**鉴权是根据url到数据库里查需要的role**，没有写死在代码里面的部分，十分灵活，需要添加、修改url、role、user信息时，**直接改数据库中的记录就可以啦**。

## 5.未登录用户、登录登出失败成功的自定义处理

前后端分离的精髓在采用相同的数据格式进行数据交互。Security框架默认会返回一个login的form表单模板，让用户填账号密码到后端进行验证。

### 5.1.AuthenticationEntryPoint接口

如果要做前后端分离，那我们肯定希望，用户没有登录直接访问时，返回一个json表示用户未登录，前端根据这个json跳转登陆页面即可。

因此要屏蔽框架自己的登录界面，使用**AuthenticationEntryPoint**接口来完成。

````java
/**
 * 匿名用户访问无权限资源时的异常  用于屏蔽Security自带的登陆界面
 */
@Component
public class CustomizeAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        Map<String, Object> map = new HashMap<>();
        map.put("code", 199);
        map.put("msg", "用户未登录");
        map.put("success", false);
        String json = JSON.toJSONString(map);

        response.setContentType("text/json;charset=utf-8");
        response.getWriter().write(json);
    }
}
````

### 5.2.AuthenticationSuccessHandler接口

用户身份验证成功后，返回一个json给前端，说明用户验证ok了。

````java
@Component
public class CustomizeAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        Map<String, Object> map = new HashMap<>();
        map.put("code", 200);
        map.put("msg", "登陆成功");
        map.put("success", true);
        String json = JSON.toJSONString(map);

        response.setContentType("text/json;charset=utf-8");
        response.getWriter().write(json);
    }
}
````

### 5.3.AuthenticationFailureHandler接口

用户账号不可用、账号密码错误等原因，返回一个json给前端。并说明验证身份失败的原因。

````java
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
````

### 5.4.LogoutSuccessHandler接口

用户登出时，返回一个json给前端。

````java
@Component
public class CustomizeLogoutSuccessHandler implements LogoutSuccessHandler {
    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        Map<String, Object> map = new HashMap<>();
        map.put("code", 300);
        map.put("msg", "已注销");
        map.put("success", true);
        String json = JSON.toJSONString(map);

        response.setContentType("text/json;charset=utf-8");
        response.getWriter().write(json);
    }
}
````

到这里，我们就实现了自定义未登录 、登陆成功失败、登出的处理。都是返回json给前端，以实现前后端分离。

### 5.5.关于前端如何登录

后端只会返回给前端json了，那么前端如何将账号密码给后端呢？

Security使用`/login`和`/logout`两个固定的url进行登录和登出。

* 当登录时，务必使用**username**和**password**两个参数，使用**post**方法访问/login，这个规则是写在源码里面的，如果没有自定义的需要就按照源码的命名规定进行传入。
* 当登出时，直接**post**方式访问/logout即可。

需要注意的是，由于我们自定义了一个前端直接访问url接口，并且采用Post方式，Security框架默认开启跨站请求伪造（CSRF），阻止跨域的post请求。因此可以将这个功能关闭，否则post请求发不过去。至于怎么关闭后面会说。

## 6.会话管理

### 6.1.SessionInformationExpiredStrategy接口

登陆后，用户可能会在另一个进程或设备上重新登陆，这样的话我们就需要注销到原来分配给用户的那个session，并通知原来的那个交互进程用户已下线的信息。

当用户长时间不操作导致Session过期时，通知前端会话已经过期，用户下线。

框架提供SessionInformationExpiredStrategy接口来实现，当用户Session被销毁或者过期时的处理操作。

````java
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
````



## 7.将所有的实现类注册到Config中

现在总结一下我们实现的接口：

* UserDetailService接口，用于查数据库，返回用户的身份、权限信息。
* FilterInvocationSecurityMetadataSource接口，根据url查询所需要的角色权限信息。
* AccessDecisionManager接口，将用户持有角色和url需要角色进行比对，完成鉴权。
* AuthenticationEntryPoint接口，匿名用户直接访问时的处理，返回前端json。
* AuthenticationSuccessHandler接口，用户身份验证成功后的处理，返回前端json。
* AuthenticationFailureHandler接口，用户身份验证失败后的处理，返回json。
* LogoutSuccessHandler接口，用户登出后的处理，返回json。
* SessionInformationExpiredStrategy接口，用户的会话被注销（挤下线或者超时）后，继续访问时的处理，返回前端json。

我们只是通过实现框架接口，自定义了这些操作，但是还没有通知框架要使用这些实现类，现在我们就要做的，就是把他们注册到设置类中。

### 7.1.WebSecurityConfigurerAdapter对象

自定义设置同样需要使用框架提供的类。通过继承WebSecurityConfigurerAdapter类，复写`void configure(AuthenticationManagerBuilder auth)`和`void configure(HttpSecurity http)`两个方法就就可以了。

首先先把我们的实现类实例注入进来：

````java
@Configuration	//配置类注解
@EnableWebSecurity	//启用Security
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
	
    //注入我们自定义的实现类
    @Resource
    private UserDetailsService userDetailsService;
    @Resource
    private AuthenticationEntryPoint authenticationEntryPoint;
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

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //待完成
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //待完成
    }
}
````



### 7.2.configure(AuthenticationManagerBuilder auth)的实现

这个configure方法是进行身份验证的。也就是说需要用到我们所定义的UserDetailsService实现类。同时，5.x以上的Security框架**要求数据库中或内存中存放的用户密码必须经过加密**！以密文形式存储，因此还需要通知configure方法我们使用的加密方法，而且注意**数据库里的密码要加密一下再insert**！

````java
	@Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService);	//通知Security，使用我们所定义的UserDetailsService实现类。
        //这样的话，Security就可以通过调用userDetailsService的loadUserByUsername方法从数据库里获取对象了。
    }

	@Bean	//加密encoder直接给Spring创建Bean即可，Security会自动去Spring容器里找PasswordEncoder对象
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();	//使用官方推荐的BCryptPasswordEncoder
    }
````



### 7.3.configure(HttpSecurity http)的实现

这个configure方法是核心的配置方法。鉴权的决定器、自定义的登录登出、匿名用户访问、会话管理都在在这里定义。

#### 7.3.1.AbstractSecurityInterceptor

在configure方法当中，我们需要先执行一个拦截器，这个拦截器完成鉴权工作。继承AbstractSecurityInterceptor类来处理：

````java
//权限拦截器
@Component
public class CustomizeAbstractSecurityInterceptor extends AbstractSecurityInterceptor implements Filter {

    @Autowired	//注入url所需要角色的查询对象
    private FilterInvocationSecurityMetadataSource securityMetadataSource;

    @Autowired	//注入鉴权的决定器
    public void setMyAccessDecisionManager(CustomizeAccessDecisionManager accessDecisionManager) {
        super.setAccessDecisionManager(accessDecisionManager);
    }

    @Override
    public Class<?> getSecureObjectClass() {
        return FilterInvocation.class;
    }

    @Override
    public SecurityMetadataSource obtainSecurityMetadataSource() {
        return this.securityMetadataSource;	//使用我们注入的securityMetadataSource
    }

    @Override	//过滤器方法，执行拦截器的拦截
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        FilterInvocation fi = new FilterInvocation(servletRequest, servletResponse, filterChain);
        invoke(fi);
    }

    public void invoke(FilterInvocation fi) throws IOException, ServletException {
        //fi里面有一个被拦截的url
        //里面调用MyInvocationSecurityMetadataSource的getAttributes(Object object)这个方法获取fi对应的所有权限
        //再调用MyAccessDecisionManager的decide方法来校验用户的权限是否足够
        InterceptorStatusToken token = super.beforeInvocation(fi);
        try {
            //执行下一个拦截器
            fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
        } finally {
            super.afterInvocation(token, null);
        }
    }
}
````

#### 7.3.2.注册到config方法中

````java
	@Resource	//拦截器别忘了注入
    private CustomizeAbstractSecurityInterceptor  securityInterceptor;

	@Override
    protected void configure(HttpSecurity http) throws Exception {
        http.cors().and().csrf().disable();	//防止登录登出的post请求被拒绝，关闭跨域保护
        
        http.authorizeRequests()	//在此进行设置
                .withObjectPostProcessor(new ObjectPostProcessor<FilterSecurityInterceptor>() {	//鉴权
                    @Override
                    public <O extends FilterSecurityInterceptor> O postProcess(O o) {
                        o.setAccessDecisionManager(accessDecisionManager);//url权限和用户权限的决定器
                        o.setSecurityMetadataSource(securityMetadataSource);//url权限所需角色的查询对象
                        return o;
                    }
                })
                .and().formLogin().permitAll()	//允许任何用户访问login接口
                .successHandler(authenticationSuccessHandler)	//自定义的登陆成功处理
                .failureHandler(authenticationFailureHandler)	//自定义的登陆失败处理
                .and().logout().permitAll()		//允许任何用户访问logout接口
                .logoutSuccessHandler(logoutSuccessHandler)
            	.deleteCookies("JSESSIONID")	//自定义的登出后的操作，同时要求登出后删除Cookie中的JSESSIONID
                .and().exceptionHandling()
            	.authenticationEntryPoint(authenticationEntryPoint) //自定义的匿名用户直接访问的处理，用于屏蔽框架自带的login界面
                .and().sessionManagement()
                .maximumSessions(1)	//只允许用户持有唯一的一个session，再申请会销毁之前的。
            	.expiredSessionStrategy(sessionInformationExpiredStrategy)	//会话失效的自定义处理
                ;
        
        http.addFilterBefore(securityInterceptor, FilterSecurityInterceptor.class);	//执行拦截器进行鉴权
    }
````

注意一下，这个Session的过期时间是通过Servlet来设定的，默认为30min。如果需要改动的话，只需要在SpringBoot的配置文件里声明即可：

> server.servlet.session.timeout=30m

## 8.总结

所有的工作就都完成了，我们通过了接口来自定义了身份验证和鉴权操作，以及登入登出成功失败、会话失效的操作，全部采用Json返回给前端。实现了前后端分离。

总结一下我们需要做的事情：

1. 数据库设计，包括用户信息、需要被Security保护的url的信息、角色信息。和他们之间的对应关系表。
2. 实现接口来自定义身份验证、鉴权操作、登入登出成功失败、会话失效的操作，全部使用json返回给前端。
3. 前端登陆登出时，用post方式访问/login和/logout两个接口即可，注意登入时携带参数的名称。
4. 将所有的实现类注册到Security框架的Configuration类中。

最后是Configuration类的全部代码：

```java
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Resource
    private UserDetailsService userDetailsService;
    @Resource
    private AuthenticationEntryPoint authenticationEntryPoint;
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
```



## 9.参考

[spring security中的AbstractSecurityInterceptor](https://blog.csdn.net/qq_43633220/article/details/108305496)

[Springboot + Spring Security 实现前后端分离登录认证及权限控制](https://blog.csdn.net/I_am_Hutengfei/article/details/100561564)

[Spring Security 工作原理概览](https://blog.csdn.net/u012702547/article/details/89629415)