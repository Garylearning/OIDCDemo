package resources.handler;

import cn.hutool.json.JSONUtil;
import resources.utils.RespJson;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * 自定义的 AccessDeniedHandler 实现，用于处理访问被拒绝的情况。
 * 当用户尝试访问他们没有权限的资源时，Spring Security 会调用此处理器。
 */
public class UnAccessDeniedHandler implements AccessDeniedHandler {







    /**
     * 处理访问被拒绝的请求，返回一个包含错误信息的 JSON 响应
     *
     * @param request HTTP 请求
     * @param response HTTP 响应
     * @param accessDeniedException 访问被拒绝的异常
     * @throws IOException 如果写入响应流时发生 I/O 错误
     * @throws ServletException 如果处理请求时发生 Servlet 异常
     */
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        // 设置响应状态为 403 (Forbidden)
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        // 设置字符编码为 UTF-8
        response.setCharacterEncoding("utf-8");
        // 设置响应内容类型为 JSON
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        // 获取响应输出流
        ServletOutputStream outputStream = response.getOutputStream();
        // 创建一个包含错误信息的 RespJson 对象
        RespJson fail = RespJson.error(HttpServletResponse.SC_FORBIDDEN,
                "UnAccessDeniedHandler-未授权, 不允许访问, uri-".concat(request.getRequestURI()));
        // 将 RespJson 对象转换为 JSON 字符串并写入响应流
        outputStream.write(JSONUtil.toJsonStr(fail).getBytes(StandardCharsets.UTF_8));

        // 刷新并关闭输出流
        outputStream.flush();
        outputStream.close();
    }
}
