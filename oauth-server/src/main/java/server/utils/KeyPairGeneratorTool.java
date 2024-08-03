package server.utils;

import java.io.FileWriter;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;




/**
 *
 * 这个猎德主要作用是生成一个RSA的密钥对  然后将公钥和私钥都 保存到PEM 的格式
 *
 *
 *
 */




public class KeyPairGeneratorTool {




    /**
     *
     *生成RSA密钥
     * 对并调用savePublicKeyToPem和savePrivateKeyToPem方法分别保存公钥和私钥。
     *
     * @param outputDirectory 输入目录
     * @param publicKeyFileName 公钥文件名
     * @param privateKeyFileName 私钥文件名
     *
     *
     */
    public static void generateKeyPairAndSaveToPem(String outputDirectory, String publicKeyFileName, String privateKeyFileName) throws Exception {
        // 生成密钥对生成器实例
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);

        // 生成密钥对
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // 保存公钥到PEM文件
        savePublicKeyToPem(outputDirectory, publicKeyFileName, keyPair.getPublic());
        // 保存私钥到PEM文件
        savePrivateKeyToPem(outputDirectory, privateKeyFileName, keyPair.getPrivate());
    }







    /**
     * 保存公钥到PEM文件。
     *
     * @param outputDirectory 输出目录
     * @param fileName        公钥文件名
     * @param publicKey       公钥对象
     * @throws IOException 如果写入文件时发生错误
     * @throws NoSuchAlgorithmException 如果指定的算法不可用
     * @throws InvalidKeySpecException 如果密钥规范无效
     */
    private static void savePublicKeyToPem(String outputDirectory, String fileName, PublicKey publicKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(publicKey.getEncoded());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        // 获取公钥实例
        PublicKey publicKeyInstance = keyFactory.generatePublic(keySpecX509);

        String pemPublicKey = "-----BEGIN PUBLIC KEY-----\n" +
                Base64.getEncoder().encodeToString(keySpecX509.getEncoded()) +
                "\n-----END PUBLIC KEY-----";

        try (FileWriter writer = new FileWriter(outputDirectory + "/" + fileName)) {
            writer.write(pemPublicKey);
        }
    }









    /**
     * 保存私钥到PEM文件。
     *
     * @param outputDirectory 输出目录
     * @param fileName        私钥文件名
     * @param privateKey      私钥对象
     * @throws InvalidKeySpecException 如果密钥规范无效
     * @throws IOException 如果写入文件时发生错误
     * @throws NoSuchAlgorithmException 如果指定的算法不可用
     */
    private static void savePrivateKeyToPem(String outputDirectory, String fileName, PrivateKey privateKey) throws InvalidKeySpecException, IOException, NoSuchAlgorithmException {
        PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(privateKey.getEncoded());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        // 获取私钥实例
        PrivateKey privateKeyInstance = keyFactory.generatePrivate(keySpecPKCS8);

        String pemPrivateKey = "-----BEGIN PRIVATE KEY-----\n" +
                Base64.getEncoder().encodeToString(keySpecPKCS8.getEncoded()) +
                "\n-----END PRIVATE KEY-----";

        try (FileWriter writer = new FileWriter(outputDirectory + "/" + fileName)) {
            writer.write(pemPrivateKey);
        }
    }





    /**
     * 主方法，用于执行密钥对生成并保存到指定目录中。
     *
     * @param args 命令行参数
     */
    public static void main(String[] args) {
        try {
            String outputDir = "D:\\data\\coding files\\java\\oauth-new-master\\oauth-server\\src\\main\\resources\\keys";//这里指定了输入的目录  在key里面
            generateKeyPairAndSaveToPem(outputDir, "public_key.pem", "private_key.pem");
            System.out.println("密钥对已成功生成并保存到 " + outputDir + " 目录下。");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}