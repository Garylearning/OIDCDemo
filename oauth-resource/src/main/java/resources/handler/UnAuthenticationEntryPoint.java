package resources.handler;

import cn.hutool.json.JSONUtil;
import resources.utils.RespJson;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * 自定义 AuthenticationEntryPoint 实现，用于处理未认证的请求。
 * 当用户尝试访问需要认证的资源，但未提供有效的认证凭证时，Spring Security 会调用此处理器
 */
@Slf4j
public class UnAuthenticationEntryPoint implements AuthenticationEntryPoint {







    /**
     * 处理未认证的请求，返回一个包含错误信息的 JSON 响应。
     *
     * @param request HTTP 请求
     * @param response HTTP 响应
     * @param authException 认证异常
     * @throws IOException 如果写入响应流时发生 I/O 错误
     * @throws ServletException 如果处理请求时发生 Servlet 异常
     */
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        // 如果异常是 InvalidBearerTokenException 类型，记录日志
        if (authException instanceof InvalidBearerTokenException) {
            log.info("Token 登录失效");
        }

        // 如果响应已经提交，返回
        if (response.isCommitted()) {
            return;
        }

        // 设置响应状态为 401 (Unauthorized)
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        // 之前的代码设置状态为 202 (Accepted)，应去掉这一行
        // response.setStatus(HttpServletResponse.SC_ACCEPTED);
        response.setCharacterEncoding("utf-8");
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        // 获取响应输出流
        ServletOutputStream outputStream = response.getOutputStream();
        // 创建一个包含错误信息的 RespJson 对象
        RespJson fail = RespJson.error(HttpServletResponse.SC_UNAUTHORIZED,
                authException.getMessage() + "-UnAuthenticationEntryPoint-认证失败, uri-" + request.getRequestURI());
        // 将 RespJson 对象转换为 JSON 字符串并写入响应流
        outputStream.write(JSONUtil.toJsonStr(fail).getBytes(StandardCharsets.UTF_8));

        // 刷新并关闭输出流
        outputStream.flush();
        outputStream.close();
    }
}
