package client.controller;

import cn.hutool.json.JSONUtil;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Controller
public class IndexController {

    /**
     * 处理根路径的请求，将用户重定向到 /index 路径。
     *
     * @return 重定向到 /index
     */
    @GetMapping("/")
    public String root() {
        return "redirect:/index";
    }














    /**
     * 处理 /index 路径的请求，获取当前用户的信息并将其传递给视图。
     *
     * @param model 用于将数据添加到视图模型中
     * @return 返回 index 视图的名称
     */
    @GetMapping("/index")
    public String index(Model model) {
        Map<String, Object> map = new HashMap<>();

        // 获取当前认证的用户信息
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        map.put("name", auth.getName()); // 将用户的名称添加到数据中

        // 获取用户的权限信息
        Collection<? extends GrantedAuthority> authorities = auth.getAuthorities();
        List<? extends GrantedAuthority> authoritiesList = authorities.stream().collect(Collectors.toList());
        map.put("authorities", authoritiesList); // 将用户的权限添加到数据中

        // 将用户信息和权限信息转换为 JSON 格式，并添加到模型中
        model.addAttribute("user", JSONUtil.toJsonStr(map));
        return "index"; // 返回视图名称
    }
}
