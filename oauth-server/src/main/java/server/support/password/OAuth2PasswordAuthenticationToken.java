package server.support.password;

import lombok.Getter;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;
import org.springframework.util.Assert;

import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class OAuth2PasswordAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

    @Getter
    private final String username;
    @Getter
    private final String password;
    @Getter
    private final Set<String> scopes;

    public OAuth2PasswordAuthenticationToken(
            // 用户名
            String username,
            // 客户端主体
            Authentication clientPrincipal,
            // 密码
            String password,
            // 附加参数
            Map<String, Object> additionalParameters,
            // 授权范围
            Set<String> scopes) {
        // 调用父类构造函数，设置授权类型为密码模式
        super(AuthorizationGrantType.PASSWORD, clientPrincipal, additionalParameters);
        // 断言用户名不为空
        Assert.hasText(username, "code cannot be empty");
        // 设置用户名
        this.username = username;
        // 设置密码
        this.password = password;
        // 设置授权范围，并确保不可修改
        this.scopes = Collections.unmodifiableSet(scopes != null ? new HashSet<>(scopes) : Collections.emptySet());
    }


}
