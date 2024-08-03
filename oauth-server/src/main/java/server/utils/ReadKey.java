package server.utils;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Objects;

/**
 * 这个类的作用是从文件中读取RSA的私钥和公钥  然后将他们转化为 private Key 和Public Key的对象
 *
 */



public class ReadKey {

    public static PrivateKey redPrivateKey() {
        try {
            // 读取私钥文件内容
            String privateKeyContent = new String(Files.readAllBytes(Paths.get(Objects.requireNonNull(ReadKey.class.getClassLoader().getResource("keys/private_key.pem")).toURI())));
            // 移除BEGIN PRIVATE KEY和END PRIVATE KEY字符串
            privateKeyContent = privateKeyContent.replace("-----BEGIN PRIVATE KEY-----", "");
            privateKeyContent = privateKeyContent.replace("-----END PRIVATE KEY-----", "");
            // 移除所有空白字符（包括换行和空格）
            privateKeyContent = privateKeyContent.replaceAll("\\s", ""); // 移除所有空白字符（包括换行和空格）
            // 将私钥内容解码为字节数组
            byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyContent);
            // 创建PKCS8EncodedKeySpec对象
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            // 获取RSA密钥工厂实例
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            // 生成私钥对象并返回
            return keyFactory.generatePrivate(keySpec);
        } catch (IOException e) {
            // 读取私钥文件时出错
            throw new RuntimeException("读取私钥文件时出错：" + e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            // 不支持的密钥算法
            throw new RuntimeException("不支持的密钥算法：" + e.getMessage());
        } catch (InvalidKeySpecException e) {
            // 无效的密钥规范
            throw new RuntimeException("无效的密钥规范：" + e.getMessage());
        } catch (URISyntaxException e) {
            // URI语法异常
            throw new RuntimeException(e);
        }
    }


    public static PublicKey redPublicKey() {
        try {
            // 读取公钥文件内容
            String publicKeyContent = new String(Files.readAllBytes(Paths.get(Objects.requireNonNull(ReadKey.class.getClassLoader().getResource("keys/public_key.pem")).toURI())));
            // 移除头部和尾部标记
            publicKeyContent = publicKeyContent.replace("-----BEGIN PUBLIC KEY-----", "");
            publicKeyContent = publicKeyContent.replace("-----END PUBLIC KEY-----", "");
            // 移除所有空白字符（包括换行和空格）
            publicKeyContent = publicKeyContent.replaceAll("\\s", "");
            // 解码Base64编码的公钥内容
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyContent);
            // 创建公钥规范
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            // 获取KeyFactory实例
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            // 生成公钥
            return keyFactory.generatePublic(keySpec);
        } catch (IOException e) {
            throw new RuntimeException("读取公钥文件时出错：" + e.getMessage(), e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("不支持的密钥算法：" + e.getMessage(), e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException("无效的密钥规范：" + e.getMessage(), e);
        } catch (URISyntaxException e) {
            throw new RuntimeException("无效的URI语法：" + e.getMessage(), e);
        }
    }

    public static void main(String[] args) {
        System.out.println(redPrivateKey());
        System.out.println(redPublicKey());
    }
}