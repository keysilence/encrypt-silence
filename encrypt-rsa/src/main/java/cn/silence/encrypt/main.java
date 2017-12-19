package cn.silence.encrypt;

import java.security.Key;
import java.util.Map;

/**
 * Created by Silence on 2017/12/15.
 */
public class main {


    public static void main(String[] args) throws Exception {

        String testString = "{\"data\":\"测试\"}";

        //初始化密钥
        Map<String, Key> map = RSACoder.initKey();
        //获取公钥
        String publicKey = RSACoder.getPublicKey(map);
        //获取私钥
        String privateKey = RSACoder.getPrivateKey(map);
        /**
         * 公钥加密，私钥解密
         */
        byte[] encryptString = RSACoder.encryptByPublicKey(testString, publicKey);
        byte[] decryptString = RSACoder.decryptByPrivateKey(encryptString, privateKey);
        //输出结果
        System.out.println(new String(decryptString));

        /**
         * 私钥加密，公钥解密
         */
        encryptString = RSACoder.encryptByPrivateKey(testString.getBytes("UTF-8"), privateKey);
        decryptString = RSACoder.decryptByPublicKey(encryptString, publicKey);
        //输出结果
        System.out.println(new String(decryptString));

        /**
         * 验签
         */
        String signedData = RSACoder.sign(testString.getBytes(), privateKey);
        boolean is = RSACoder.verify(testString.getBytes(), publicKey, signedData);
        System.out.println(is);

        /**
         * 用无Base64的密钥加解密
         */
        encryptString = RSACoder.encryptByPublicKey(testString, RSACoder.getPublicKeyNoBase64(map));
        decryptString = RSACoder.decryptByPrivateKey(encryptString, RSACoder.getPrivateKeyNoBase64(map));
        System.out.println(new String(decryptString));

    }

}
