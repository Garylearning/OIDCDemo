package server.utils;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
//作用是获取认证过程中获取已经认证的客户端的信息 如果客户端的信息是无效的  就抛出异常
public class OAuth2AuthenticationProviderUtils {
    private OAuth2AuthenticationProviderUtils() {
    }












    /**
     * 获取已认证的客户端信息，如果客户端信息无效，则抛出异常
     *
     * @param authentication 当前的认证信息
     * @return 返回已认证的客户端信息，
     * @throws OAuth2AuthenticationException 如果客户端无效或未认证
     */
    public static OAuth2ClientAuthenticationToken getAuthenticatedClientElseThrowInvalidClient(Authentication authentication) {
        // 定义一个OAuth2ClientAuthenticationToken类型的变量clientPrincipal，用于存储客户端主体
        OAuth2ClientAuthenticationToken clientPrincipal = null;
        // 判断authentication中的主体是否为OAuth2ClientAuthenticationToken类型
        if (OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication.getPrincipal().getClass())) {
            // 如果是，则将其转换为OAuth2ClientAuthenticationToken类型，并赋值给clientPrincipal
            clientPrincipal = (OAuth2ClientAuthenticationToken) authentication.getPrincipal();
        }

        // 判断clientPrincipal是否不为null且已经认证通过
        if (clientPrincipal != null && clientPrincipal.isAuthenticated()) {
            // 如果是，则返回clientPrincipal
            return clientPrincipal;
        } else {
            // 否则，抛出OAuth2AuthenticationException异常，表示客户端无效
            throw new OAuth2AuthenticationException("invalid_client");
        }
    }

}
