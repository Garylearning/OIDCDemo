package server.config;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.annotation.Resource;
import javax.sql.DataSource;

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class ServerSecurityConfig {

    @Resource
    private DataSource dataSource;

    /**
     * Spring Security 的过滤器链，用于 Spring Security 的身份认证。
     *
     * @param http Spring Security 的 HttpSecurity 对象，用于配置 HTTP 安全性
     * @return SecurityFilterChain 返回一个配置好的 SecurityFilterChain 对象
     * @throws Exception 可能抛出的异常
     */
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        // 这里说明了放行了 /api/** 和 /login/** 的请求，其他所有请求都需要认证
                        .antMatchers("/api/**", "/login/**").permitAll()
                        // 其他任何请求都需要认证
                        .anyRequest().authenticated()
                )
                // 设置登录表单页面
                .formLogin(Customizer.withDefaults());

        return http.build();
    }
    /**
     * 创建并返回一个 BCryptPasswordEncoder 实例
     *
     * @return BCryptPasswordEncoder 返回一个用于加密密码的 BCryptPasswordEncoder
     */
    @Bean
    BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    /**
     * 创建一个 UserDetailsManager 对象。
     *
     * @return UserDetailsManager 返回一个管理用户信息的 UserDetailsManager
     */
    @Bean
    UserDetailsManager userDetailsManager() {
        // 使用 JdbcUserDetailsManager 来实现 UserDetailsManager 接口
        JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager(dataSource);

        // 创建一个 UserDetails 对象
        UserDetails userDetails = User.builder()
                // 设置密码编码器为 BCryptPasswordEncoder
                .passwordEncoder(s -> new BCryptPasswordEncoder().encode(s))
                // 设置用户名
                .username("123456")
                // 设置密码
                .password("123456")
                // 设置角色为 ADMIN
                .roles("ADMIN")
                // 构建 UserDetails 对象
                .build();

        // 判断用户是否存在
        if (!userDetailsManager.userExists(userDetails.getUsername())) {
            // 如果用户不存在，则创建用户
            userDetailsManager.createUser(userDetails);
        }

        // 返回 UserDetailsManager 对象
        return userDetailsManager;
    }

}

