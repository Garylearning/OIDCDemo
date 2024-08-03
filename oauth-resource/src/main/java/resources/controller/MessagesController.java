package resources.controller;

import resources.utils.RespJson;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MessagesController {




    /**
     * 处理对 /resource1 的 GET 请求。
     *
     * @return 返回一个包含 "服务A -> 资源1 -> 读权限" 的成功响应。
     */
    @GetMapping("/resource1")
    public RespJson<String> getResource1(){
        return RespJson.success("服务A -> 资源1 -> 读权限");
    }







    /**
     * 处理对 /resource2 的 GET 请求。
     *
     * @return 返回一个包含 "服务A -> 资源2 -> 写权限" 的成功响应。
     */
    @GetMapping("/resource2")
    public RespJson<String> getResource2(){
        return RespJson.success("服务A -> 资源2 -> 写权限");
    }












    /**
     * 处理对 /resource3 的 GET 请求。
     *
     * @return 返回一个包含 "服务A -> 资源3 -> profile 权限" 的成功响应。
     */
    @GetMapping("/resource3")
    public RespJson<String> resource3(){
        return RespJson.success("服务A -> 资源3 -> profile 权限");
    }






    /**
     * 处理对 /api/publicResource 的 GET 请求。
     *
     * @return 返回一个包含 "服务A -> 公共资源" 的成功响应。
     */
    @GetMapping("/api/publicResource")
    public RespJson<String> publicResource() {
        return RespJson.success("服务A -> 公共资源");
    }
}
