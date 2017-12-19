package cn.silence.encrypt;

import org.apache.commons.codec.binary.Base64;
import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by Silence on 2017/12/15.
 */
public class RSACoder {

    public static final String KEY_ALGORITHM = "RSA";
    /**
     * DSA：SHA1withDSA
     * RSA：MD2withRSA, MD5withRSA, or SHA1withRSA
     */
    public static final String SIGNATURE_ALGORITHM = "MD5withRSA";

    private static final String PUBLIC_KEY = "PublicKey";
    private static final String PRIVATE_KEY = "PrivateKey";

    /**
     * Base64解码密钥
     * @param key       密钥
     * @return byte[]   解码后密钥
     */
    public static byte[] decryptBASE64(String key) {
        return Base64.decodeBase64(key);
    }

    /**
     * Base64编码密钥
     * @param bytes    密钥
     * @return String  编码后密钥
     */
    public static String encryptBASE64(byte[] bytes) {

        return Base64.encodeBase64String(bytes);

    }

    /**
     * 初始化密钥
     *
     * @return Map<String, Key> 初始化后密钥数据
     * @throws Exception
     */
    public static Map<String, Key> initKey() throws Exception {

        //密钥对生成器，参数为算法名称，KeyPairGenerator包含四中算法：DiffieHellman、DSA、RSA和EC
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        //初始化密钥大小，单位是位数bits
        keyPairGen.initialize(2048);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        Map<String, Key> keyMap = new HashMap<String, Key>();
        //公钥
        keyMap.put(PUBLIC_KEY, keyPair.getPublic());
        //私钥
        keyMap.put(PRIVATE_KEY, keyPair.getPrivate());

        return keyMap;

    }

    /**
     * 获取私钥（BASE64编码后）
     *
     * @param keyMap    已初始化密钥数据
     * @return String   私钥
     * @throws Exception
     */
    public static String getPrivateKey(Map<String, Key> keyMap)
            throws Exception {

        Key key = keyMap.get(PRIVATE_KEY);

        return encryptBASE64(key.getEncoded());

    }

    /**
     * 获取公钥（BASE64编码后）
     *
     * @param keyMap    已初始化密钥数据
     * @return String   公钥
     * @throws Exception
     */
    public static String getPublicKey(Map<String, Key> keyMap)
            throws Exception {

        Key key = keyMap.get(PUBLIC_KEY);

        return encryptBASE64(key.getEncoded());

    }

    /**
     * 获取私钥对象
     *
     * @param keyMap   已初始化密钥数据
     * @return Key     私钥对象
     * @throws Exception
     */
    public static Key getPrivateKeyNoBase64(Map<String, Key> keyMap)
            throws Exception {

        return keyMap.get(PRIVATE_KEY);

    }

    /**
     * 获取公钥对象
     *
     * @param keyMap   已初始化密钥数据
     * @return Key     公钥对象
     * @throws Exception
     */
    public static Key getPublicKeyNoBase64(Map<String, Key> keyMap)
            throws Exception {

        return keyMap.get(PUBLIC_KEY);

    }

    /**
     * 用私钥对数据进行数字签名
     *
     * @param data       原始数据
     * @param privateKey 私钥
     * @return String    签名后数据
     * @throws Exception
     */
    public static String sign(byte[] data, String privateKey) throws Exception {

        //解码由Base64编码的私钥
        byte[] keyBytes = decryptBASE64(privateKey);
        /**
         * 大家肯定会对如下操作有些困惑，如下操作是还原私钥的过程，因为初始化生成私钥后对私钥进行了Base64编码并生成字符串，
         * 这里需要将编码后的私钥字符串还原成具体的私钥对象
         */
        //借助PKCS8EncodedKeySpec还原私钥
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        //指定加密算法RSA
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        //获取私钥对象
        PrivateKey priKey = keyFactory.generatePrivate(pkcs8KeySpec);
        /**
         * 对原始数据生成数字签名
         */
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(priKey);
        signature.update(data);

        return encryptBASE64(signature.sign());

    }

    /**
     * 验证签名后数据
     *
     * @param data      原始数据
     * @param publicKey 公钥
     * @param sign      签名后数据
     * @return boolean  验证结果（成功：true 失败：false）
     * @throws Exception
     */
    public static boolean verify(byte[] data, String publicKey, String sign) throws Exception {

        //解码由Base64编码的公钥
        byte[] keyBytes = decryptBASE64(publicKey);
        /**
         * 如下操作即还原公钥的过程
         */
        //借助X509EncodedKeySpec还原公钥
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        //指定的加密算法RSA
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        //获取公钥对象
        PublicKey pubKey = keyFactory.generatePublic(keySpec);
        /**
         * 根据原始数据验证签名后数据
         */
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(pubKey);
        signature.update(data);

        return signature.verify(decryptBASE64(sign));

    }

    /**
     * 用公钥加密数据
     *
     * @param data     原始数据
     * @param key      公钥
     * @return byte[]  加密后数据
     * @throws Exception
     */
    public static byte[] encryptByPublicKey(String data, String key) throws Exception {

        //解码由Base64编码的公钥
        byte[] keyBytes = decryptBASE64(key);
        /**
         * 如下操作即还原公钥的过程
         */
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key publicKey = keyFactory.generatePublic(x509KeySpec);
        //对数据加密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        return cipher.doFinal(data.getBytes());

    }

    /**
     * 用私钥解密数据
     *
     * @param data     加密后数据
     * @param key      私钥
     * @return byte[]  解密后数据
     * @throws Exception
     */
    public static byte[] decryptByPrivateKey(byte[] data, String key) throws Exception {

        //解码由Base64编码的私钥
        byte[] keyBytes = decryptBASE64(key);
        /**
         * 如下操作即还原私钥的过程
         */
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key privateKey = keyFactory.generatePrivate(pkcs8KeySpec);
        //对数据解密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        return cipher.doFinal(data);

    }

//    /**
//     * 用私钥解密数据
//     *
//     * @param data     加密后数据
//     * @param key      私钥
//     * @return byte[]  解密后数据
//     * @throws Exception
//     */
//    public static byte[] decryptByPrivateKey(String data, String key) throws Exception {
//
//        return decryptByPrivateKey(decryptBASE64(data),key);
//
//    }

    /**
     * 用私钥加密数据
     *
     * @param data     原始数据
     * @param key      私钥
     * @return byte[]  加密后数据
     * @throws Exception
     */
    public static byte[] encryptByPrivateKey(byte[] data, String key) throws Exception {

        //解码由Base64编码的私钥
        byte[] keyBytes = decryptBASE64(key);
        /**
         * 如下操作即还原私钥的过程
         */
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key privateKey = keyFactory.generatePrivate(pkcs8KeySpec);
        //对数据加密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);

        return cipher.doFinal(data);

    }

    /**
     * 用公钥解密数据
     *
     * @param data     加密后数据
     * @param key      公钥
     * @return byte[]  解密后数据
     * @throws Exception
     */
    public static byte[] decryptByPublicKey(byte[] data, String key) throws Exception {

        //解码由Base64编码的公钥
        byte[] keyBytes = decryptBASE64(key);
        /**
         * 如下操作即还原公钥的过程
         */
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key publicKey = keyFactory.generatePublic(x509KeySpec);
        //对数据解密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, publicKey);

        return cipher.doFinal(data);

    }

    /**
     * 用公钥对象加密
     *
     * @param data     原始数据
     * @param key      公钥对象
     * @return byte[]  加密后数据
     * @throws Exception
     */
    public static byte[] encryptByPublicKey(String data, Key key)
            throws Exception {

        //对数据加密
        Cipher cipher = Cipher.getInstance(KEY_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);

        return cipher.doFinal(data.getBytes());

    }

    /**
     * 用私钥对象解密
     *
     * @param data     加密后数据
     * @param key      私钥对象
     * @return byte[]  解密后数据
     * @throws Exception
     */
    public static byte[] decryptByPrivateKey(byte[] data, Key key) throws Exception{

        //对数据解密
        Cipher cipher = Cipher.getInstance(KEY_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);

        return cipher.doFinal(data);

    }

}