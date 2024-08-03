package server.support.password;

import server.utils.OAuth2EndpointUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.*;

public class OAuth2PasswordAuthenticationConverter implements AuthenticationConverter {

    public final String ACCESS_TOKEN_REQUEST_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";
    /**
     * 将 HTTP 请求转换为 OAuth2 密码模式认证的 Authentication 对象。
     *
     * @param request 包含 OAuth2 请求参数的 HttpServletRequest 对象
     * @return 转换后的 Authentication 对象。如果请求的 grant_type 不是密码模式，则返回 null。
     *
     */
    @Override
    public Authentication convert(HttpServletRequest request) {
        //验证是否是密码模式
        String grantType = request.getParameter("grant_type");
        if (!AuthorizationGrantType.PASSWORD.getValue().equals(grantType)) {
            return null;
        } else {
            // 获取客户端认证信息
            Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();
            //获取请求中所有参数
            MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getParameters(request);
            //获取用户名信息
            String username = parameters.getFirst("username");
            //验证用户名是否为空，且只有一个
            if (!StringUtils.hasText(username) || parameters.get("password").size() != 1) {
                OAuth2EndpointUtils.throwError("invalid_request", "username", null);
            }
            //获取密码信息
            String password = parameters.getFirst("password");
            //验证密码是否为空，且只有一个
            if (!StringUtils.hasText(password) || parameters.get("password").size() != 1) {
                OAuth2EndpointUtils.throwError("invalid_request", "password", null);
            }
            //获取其他参数
            Map<String, Object> additionalParameters = new HashMap<>();
            parameters.forEach((key, value) -> {
                if (!key.equals("grant_type") && !key.equals("client_id") && !key.equals("username") && !key.equals("password")) {
                    additionalParameters.put(key, value.get(0));
                }
            });
            // 获取 scope 参数
            String scope = parameters.getFirst(OAuth2ParameterNames.SCOPE);
            if (StringUtils.hasText(scope) && parameters.get(OAuth2ParameterNames.SCOPE).size() != 1) {
                OAuth2EndpointUtils.throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.SCOPE, ACCESS_TOKEN_REQUEST_ERROR_URI);
            }
            // 解析 scope 参数值
            Set<String> requestedScopes = null;
            if (StringUtils.hasText(scope)) {
                requestedScopes = new HashSet<>(Arrays.asList(StringUtils.delimitedListToStringArray(scope, " ")));
            }
            // 返回 OAuth2PasswordAuthenticationToken 对象
            return new OAuth2PasswordAuthenticationToken(username, clientPrincipal, password, additionalParameters, requestedScopes);
        }
    }

}
