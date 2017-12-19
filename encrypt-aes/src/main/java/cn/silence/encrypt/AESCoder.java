package cn.silence.encrypt;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

/**
 * Created by Silence on 2017/12/19.
 */
public class AESCoder {

    /**
     * 定义加密方式为AES
     */
    private final static String KEY_AES = "AES";

    //保存的全局种子
    private static byte[] SEED = null;

    /**
     * 加密数据
     * @param data
     * @param password
     * @return
     * @throws Exception
     */
    public static byte[] encrypt(String data, String password) throws Exception {

        //密钥生成器，参数为算法名称，KeyGenerator包含五种算法：AES (128)、DES (56)、DESede (168)、HmacSHA1和HmacSHA256
        KeyGenerator keyGenerator = KeyGenerator.getInstance(KEY_AES);

        //根据SHA1PRNG算法生成伪随机数
        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");

        //设置随机数生成所使用的种子
        secureRandom.setSeed(password.getBytes());

        //上面是将传入的paasword作为生成密钥的种子，当然也可以像如下这样，生成随机的种子，但是这个种子要跟解密时候的种子一直，
        //因此这里设置了全局变量，当然这么做并不适合分布式部署的场合，因此慎用
//        SEED = secureRandom.generateSeed(8);
//        secureRandom.setSeed(SEED);

        //初始化密钥生成器
        keyGenerator.init(128, secureRandom);

        //生成对称密钥
        SecretKey secretKey = keyGenerator.generateKey();

        //获取对称密钥字节数组
        byte[] encodeFormat = secretKey.getEncoded();

        //根据对称密钥字节数组生成AES密钥
        SecretKeySpec secretKeySpec = new SecretKeySpec(encodeFormat, KEY_AES);

        //对数据加密
        Cipher cipher = Cipher.getInstance(KEY_AES);

        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

        return cipher.doFinal(data.getBytes("UTF-8"));

    }

    public static byte[] decrypt(byte[] data, String password) throws Exception {

        //密钥生成器，参数为算法名称，KeyGenerator包含五种算法：AES (128)、DES (56)、DESede (168)、HmacSHA1和HmacSHA256
        KeyGenerator keyGenerator = KeyGenerator.getInstance(KEY_AES);

        //根据SHA1PRNG算法生成伪随机数
        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");

        //设置随机数生成所使用的种子
        secureRandom.setSeed(password.getBytes());

        //同加密时对应的描述
//        secureRandom.setSeed(SEED);

        //初始化密钥生成器
        keyGenerator.init(128, secureRandom);

        //生成对称密钥
        SecretKey secretKey = keyGenerator.generateKey();

        //获取对称密钥字节数组
        byte[] encodeFormat = secretKey.getEncoded();

        //根据对称密钥字节数组生成AES密钥
        SecretKeySpec secretKeySpec = new SecretKeySpec(encodeFormat, KEY_AES);

        //对数据解密
        Cipher cipher = Cipher.getInstance(KEY_AES);

        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);

        return cipher.doFinal(data);

    }

}
