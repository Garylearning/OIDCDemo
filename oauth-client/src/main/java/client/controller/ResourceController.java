package client.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

@Slf4j
@RestController
public class ResourceController {

    /**
     * 处理对 /server/a/resource1 路径的 GET 请求，获取 Server A 上的资源1。
     *
     * @param oAuth2AuthorizedClient 已授权的 OAuth2 客户端
     * @return Server A 上的资源1
     */
    @GetMapping("/server/a/resource1")
    public String getServerARes1(@RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient oAuth2AuthorizedClient) {
        return getServer("http://localhost:8001/resource1", oAuth2AuthorizedClient);
    }









    /**
     * 处理对 /server/a/resource2 路径的 GET 请求，获取 Server A 上的资源2。
     *
     * @param oAuth2AuthorizedClient 已授权的 OAuth2 客户端
     * @return Server A 上的资源2
     */
    @GetMapping("/server/a/resource2")
    public String getServerARes2(@RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient oAuth2AuthorizedClient) {
        return getServer("http://localhost:8001/resource2", oAuth2AuthorizedClient);
    }








    /**
     * 处理对 /server/a/resource3 路径的 GET 请求，获取 Server B 上的资源3。
     *
     * @param oAuth2AuthorizedClient 已授权的 OAuth2 客户端
     * @return Server B 上的资源3
     */
    @GetMapping("/server/a/resource3")
    public String getServerBRes1(@RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient oAuth2AuthorizedClient) {
        return getServer("http://localhost:8001/resource3", oAuth2AuthorizedClient);
    }








    /**
     * 处理对 /server/a/publicResource 路径的 GET 请求，获取 Server B 上的公共资源。
     *
     * @param oAuth2AuthorizedClient 已授权的 OAuth2 客户端
     * @return Server B 上的公共资源
     */
    @GetMapping("/server/a/publicResource")
    public String getServerBRes2(@RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient oAuth2AuthorizedClient) {
        return getServer("http://localhost:8001/api/publicResource", oAuth2AuthorizedClient);
    }








    /**
     * 使用 OAuth2 授权客户端的访问令牌请求指定 URL 的资源。
     *
     * @param url 请求的资源 URL
     * @param oAuth2AuthorizedClient 已授权的 OAuth2 客户端
     * @return 请求响应的字符串
     */
    private String getServer(String url, OAuth2AuthorizedClient oAuth2AuthorizedClient) {
        log.info("getServer");
        // 获取访问令牌
        String tokenValue = oAuth2AuthorizedClient.getAccessToken().getTokenValue();

        // 使用 WebClient 发起请求
        Mono<String> stringMono = WebClient.builder()
                .defaultHeader("Authorization", "Bearer " + tokenValue) // 设置 Authorization 头
                .build()
                .get()
                .uri(url)
                .retrieve()
                .bodyToMono(String.class);

        // 阻塞并获取响应
        return stringMono.block();
    }
}
