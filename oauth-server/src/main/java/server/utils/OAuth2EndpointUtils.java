package server.utils;

import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

/**
 * 用于处理OAuth2.0认证过程中的请求参数和错误处理。
 */
public class OAuth2EndpointUtils {

    /**
     * 从HttpServletRequest中获取所有请求参数，并将它们转换为MultiValueMap格式。
     *
     * @param request HttpServletRequest对象，包含请求参数
     * @return MultiValueMap，包含所有请求参数
     */
    public static MultiValueMap<String, String> getParameters(HttpServletRequest request) {
        // 获取请求参数映射表
        Map<String, String[]> parameterMap = request.getParameterMap();
        // 创建一个可修改的键值对集合
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>(parameterMap.size());
        // 遍历参数映射表
        parameterMap.forEach((key, values) -> {
            // 如果参数值数组长度大于0
            if (values.length > 0) {
                // 遍历参数值数组
                for (String value : values) {
                    // 将参数名和参数值添加到集合中
                    parameters.add(key, value);
                }
            }
        });
        // 返回参数集合
        return parameters;
    }










    /**
     * 抛出OAuth2AuthenticationException异常，包含指定的错误码、错误参数名和错误URI。
     *
     * @param errorCode      错误码
     * @param parameterName  参数名
     * @param errorUri       URI
     */
    public static void throwError(String errorCode, String parameterName, String errorUri) {
        // 创建一个OAuth2Error对象，包含错误码、错误信息和错误URI
        OAuth2Error error = new OAuth2Error(errorCode, "OAuth 2.0 Parameter: " + parameterName, errorUri);
        // 抛出一个OAuth2AuthenticationException异常，包含上述创建的OAuth2Error对象
        throw new OAuth2AuthenticationException(error);
    }

}
