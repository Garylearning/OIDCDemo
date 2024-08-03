package server.config;

import server.support.password.OAuth2PasswordAuthenticationConverter;
import server.support.password.OAuth2PasswordAuthenticationProvider;
import server.utils.ReadKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.UUID;

@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {



    /**
     * 配置Spring Security过滤链，定义了HTTP请求的安全性。
     *
     * @param http HttpSecurity对象，用于配置基于HTTP的安全性
     * @return SecurityFilterChain 安全过滤链
     * @throws Exception 抛出异常
     */
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)//这里表示这个bean会被优先加载
    //用来配置spring security过滤链  定义了http请求的安全性
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        // 用来定义授权服务器的配置内容
        OAuth2AuthorizationServerConfigurer configurer = new OAuth2AuthorizationServerConfigurer();
        //这里配置了令牌端点的行为 将访问令牌请求转化为 Authentication 对象。
        configurer.tokenEndpoint(tokenEndpoint -> {
                    tokenEndpoint.accessTokenRequestConverter(new OAuth2PasswordAuthenticationConverter());
                })
                 //自定义授权页面  在这个地方 用户的授权过程都会被引导到这个界面
                //.authorizationEndpoint(authorizationEndpoint -> authorizationEndpoint.consentPage(CUSTOM_CONSENT_PAGE_URI))
                // Enable OpenID Connect 1.0, 启用 OIDC 1.0
                //启动OIDC
                .oidc(Customizer.withDefaults());


        // 获取授权服务器相关的请求端点  这里的端点包括授权端点和令牌端点等
        RequestMatcher endpointsMatcher = configurer.getEndpointsMatcher();

        http
                // 这里说明只会拦截和授权服务器相关联的消息请求
                .requestMatcher(endpointsMatcher)
                // 这里说明拦载到的请求都需要认证
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                // 忽略掉相关端点的 CSRF(跨站请求): 对授权端点的访问可以是跨站的
                .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
                //这里进行一个异常处理  没有认证的请求多将重新定向到/login
                .exceptionHandling(exceptions ->
                        exceptions.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
                )
                //这里配置了一个资源服务器进行JWT的认证
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
                // 应用授权服务器的配置
                .apply(configurer)
                .and()
                // 登出处理
                .logout().deleteCookies("JSESSIONID")
                .invalidateHttpSession(true); // SSO登出成功处理;
        //这里就构造一个安全过滤链
        DefaultSecurityFilterChain securityFilterChain = http.build();
        // 注入自定义授权模式实现
        http.authenticationProvider(
                new OAuth2PasswordAuthenticationProvider(
                        //这里用来处理OAuth2的授权请求
                        http.getSharedObject(OAuth2AuthorizationService.class),
                        //这里生成JWT令牌
                        http.getSharedObject(JwtGenerator.class),
                        //生成刷新令牌
                        new OAuth2RefreshTokenGenerator(),
                        //管理认证流程
                        http.getSharedObject(AuthenticationManager.class)
                ));

        return securityFilterChain;
    }





    /**
     * 注册客户端应用程序。
     * 对应 oauth2_registered_client 表。
     *
     * @param jdbcTemplate 用于与数据库交互的 JdbcTemplate 对象
     * @return RegisteredClientRepository 注册客户端的存储库
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        //使用 JdbcTemplate 来初始化 JdbcRegisteredClientRepository，它是一个用于管理客户端注册信息的存储库。
        JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);



        //配置令牌的存活时间、是否复用刷新令牌、刷新令牌的存活时间等。
        TokenSettings tokenSettings = TokenSettings.builder()
                // 令牌存活时间：2小时
                .accessTokenTimeToLive(Duration.ofHours(2))
                // 令牌可以刷新，重新获取
                .reuseRefreshTokens(true)
                // 刷新时间：30天（30天内当令牌过期时，可以用刷新令牌重新申请新令牌，不需要再认证）
                .refreshTokenTimeToLive(Duration.ofDays(30))
                .build();





        // 客户端相关配置
        ClientSettings clientSettings = ClientSettings.builder()
                // 这里设置了客户端需要用户的授权确认
                .requireAuthorizationConsent(true)
                .build();



        //这里是注册一个新的客户端
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                // 设置客户端 ID 和客户端密钥，使用 BCryptPasswordEncoder 进行加密。
                .clientId("messaging-client")
                .clientSecret(new BCryptPasswordEncoder().encode("secret"))
//                .clientSecret("{noop}secret")
                // 授权方法
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                // 授权模式（授权码模式）
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                // 刷新令牌（授权码模式）
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                // 回调地址：授权服务器向当前客户端响应时调用下面地址, 不在此列的地址将被拒绝, 只能使用IP或域名
                .redirectUri("http://localhost:8000/login/oauth2/code/messaging-client-oidc")
                // OIDC 支持
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                // 授权范围（当前客户端的授权范围）
                .scope("message.read")
                .scope("message.write")
                // JWT（Json Web Token）配置项
                .tokenSettings(tokenSettings)
                // 客户端配置项
                .clientSettings(clientSettings)
                .build();

        //检查是否已经存在相同 clientId 的客户端，如果不存在，则保存新创建的客户端信息
        if (registeredClientRepository.findByClientId("messaging-client") == null) {
            registeredClientRepository.save(registeredClient);
        }
        return registeredClientRepository;
    }

    /**
     * 令牌的发放记录, 对应 oauth2_authorization 表。
     *
     * @param jdbcTemplate 用于与数据库交互的 JdbcTemplate 对象
     * @param registeredClientRepository 注册客户端的存储库
     * @return OAuth2AuthorizationService 用于管理OAuth2授权信息的服务
     */
    @Bean
    public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
    }


    /**
     * 把资源拥有者授权确认操作保存到数据库, 对应 oauth2_authorization_consent 表。
     *
     * @param jdbcTemplate 用于与数据库交互的 JdbcTemplate 对象
     * @param registeredClientRepository 注册客户端的存储库
     * @return OAuth2AuthorizationConsentService 用于管理OAuth2授权同意信息的服务
     */
    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
    }


    /**
     * 加载 JWT 资源, 用于生成令牌。
     *
     * @return JWKSource<SecurityContext> 用于选择 JWKSet 中的密钥
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        // 从密钥对中获取公钥和私钥
        RSAPublicKey publicKey = (RSAPublicKey) ReadKey.redPublicKey();
        RSAPrivateKey privateKey = (RSAPrivateKey) ReadKey.redPrivateKey();

        // 创建 RSAKey 对象，设置公钥、私钥和 keyID
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();

        // 创建 JWKSet 对象，并添加 rsaKey
        JWKSet jwkSet = new JWKSet(rsaKey);

        // 返回 JWKSource 对象，用于选择 JWKSet 中的密钥
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    /**
     * JWT 解码。
     *
     * @param jwkSource 用于选择 JWKSet 中的密钥的 JWKSource 对象
     * @return JwtDecoder 用于解码 JWT 令牌的解码器
     */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        // 调用 OAuth2AuthorizationServerConfiguration 的 jwtDecoder 方法，传入 jwkSource 参数，返回 JwtDecoder 对象
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }


    /**
     * AuthorizationServerS 的相关配置。
     *
     * @return AuthorizationServerSettings 授权服务器的设置
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        // 使用建造者模式创建 AuthorizationServerSettings 对象
        return AuthorizationServerSettings.builder().build();
    }


}

