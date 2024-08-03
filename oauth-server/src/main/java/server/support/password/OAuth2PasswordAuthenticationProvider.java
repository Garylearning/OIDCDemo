package server.support.password;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import server.utils.OAuth2AuthenticationProviderUtils;

import java.security.Principal;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

public class OAuth2PasswordAuthenticationProvider implements AuthenticationProvider {

    private static final Logger LOGGER = LogManager.getLogger(OAuth2PasswordAuthenticationProvider.class);

    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1";

    private final OAuth2AuthorizationService authorizationService;

    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

    private final AuthenticationManager authenticationManager;

    private final OAuth2TokenGenerator<? extends OAuth2Token> refreshTokenGenerator;

    public OAuth2PasswordAuthenticationProvider(OAuth2AuthorizationService authorizationService,
                                                JwtGenerator tokenGenerator,
                                                OAuth2RefreshTokenGenerator refreshTokenGenerator,
                                                AuthenticationManager authenticationManager) {
        // 断言authorizationService不为空
        Assert.notNull(authorizationService, "authorizationService cannot be null");
        // 断言tokenGenerator不为空
        Assert.notNull(tokenGenerator, "tokenGenerator cannot be null");
        // 将传入的authorizationService赋值给当前对象的authorizationService成员变量
        this.authorizationService = authorizationService;
        // 将传入的tokenGenerator赋值给当前对象的tokenGenerator成员变量
        this.tokenGenerator = tokenGenerator;
        // 将传入的refreshTokenGenerator赋值给当前对象的refreshTokenGenerator成员变量
        this.refreshTokenGenerator = refreshTokenGenerator;
        // 将传入的authenticationManager赋值给当前对象的authenticationManager成员变量
        this.authenticationManager = authenticationManager;
    }


    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // 类型转换
        OAuth2PasswordAuthenticationToken authenticationToken = (OAuth2PasswordAuthenticationToken) authentication;
        // 获取客户端认证信息
        OAuth2ClientAuthenticationToken clientPrincipal = OAuth2AuthenticationProviderUtils.getAuthenticatedClientElseThrowInvalidClient(
                authenticationToken);
        // 获取客户端信息
        RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();
        // 断言客户端信息不为空
        assert registeredClient != null;
        //验证是否支持密码模式
        if (!registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.PASSWORD)) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }
        // 获取客户端认证方法
        Set<String> authorizedScopes = new LinkedHashSet<>();
        if (!CollectionUtils.isEmpty(authenticationToken.getScopes())) {
            for (String requestedScope : authenticationToken.getScopes()) {
                if (!registeredClient.getScopes().contains(requestedScope)) {
                    throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE);
                }
            }
            authorizedScopes = new LinkedHashSet<>(authenticationToken.getScopes());
        }
        // 获取用户名
        String username = authenticationToken.getUsername();
        // 获取密码
        String password = authenticationToken.getPassword();
        // 创建用户名密码认证实体
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(username, password);
        // 认证
        Authentication usernamePasswordAuthentication = authenticationManager
                .authenticate(usernamePasswordAuthenticationToken);
        // 创建token上下文
        DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(usernamePasswordAuthentication)
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .authorizedScopes(authorizedScopes)
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .authorizationGrant(authenticationToken);
        // 创建授权
        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization
                .withRegisteredClient(registeredClient)
                .principalName(usernamePasswordAuthentication.getName())
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .authorizedScopes(authorizedScopes);
        // 创建token上下文
        OAuth2TokenContext tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.ACCESS_TOKEN).build();
        // 生成token
        OAuth2Token generatedAccessToken = this.tokenGenerator.generate(tokenContext);
        // 判断生成的token是否为空
        if (generatedAccessToken == null) {
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                    "The token generator failed to generate the access token.", ERROR_URI);
            throw new OAuth2AuthenticationException(error);
        }
        // 创建accessToken
        OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                generatedAccessToken.getTokenValue(), generatedAccessToken.getIssuedAt(),
                generatedAccessToken.getExpiresAt(), tokenContext.getAuthorizedScopes());
        // 判断生成的token是否为ClaimAccessor类型
        if (generatedAccessToken instanceof ClaimAccessor) {
            authorizationBuilder.token(accessToken, (metadata) -> {
                        metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, ((ClaimAccessor) generatedAccessToken).getClaims());
                    })
                    .attribute(Principal.class.getName(), usernamePasswordAuthentication);
        } else {
            authorizationBuilder.accessToken(accessToken);
        }
        // 创建refreshToken
        OAuth2RefreshToken refreshToken = null;
        // 判断是否支持刷新令牌
        if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN) && !clientPrincipal.getClientAuthenticationMethod().equals(ClientAuthenticationMethod.NONE)) {
            tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.REFRESH_TOKEN).build();
            OAuth2Token generatedRefreshToken = this.refreshTokenGenerator.generate(tokenContext);
            if (!(generatedRefreshToken instanceof OAuth2RefreshToken)) {
                OAuth2Error error = new OAuth2Error("server_error", "The token generator failed to generate the refresh token.", "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2");
                throw new OAuth2AuthenticationException(error);
            }
            refreshToken = (OAuth2RefreshToken) generatedRefreshToken;
            authorizationBuilder.refreshToken(refreshToken);
        }
        // 创建授权
        OAuth2Authorization authorization = authorizationBuilder.build();
        // 保存授权
        this.authorizationService.save(authorization);

        LOGGER.debug("returning OAuth2AccessTokenAuthenticationToken");
        // 创建认证
        return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken, refreshToken, Collections.emptyMap());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        // 判断传入的authentication对象是否是指定类型或其子类的实例
        return OAuth2PasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }

}
