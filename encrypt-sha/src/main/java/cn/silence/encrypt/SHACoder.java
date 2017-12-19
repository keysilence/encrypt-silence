package cn.silence.encrypt;

import java.security.MessageDigest;

/**
 * Created by Silence on 2017/12/18.
 * SHA-1是SHA的升级版本，是一项单向加密技术，如MD5，生成不可逆的结果，可用于验证签名领域
 */
public class SHACoder {

    /**
     * 定义加密方式为SHA-1
     */
    private final static String KEY_SHA_1 = "SHA-1";

    /**
     * 全局数组
     */
    private final static String[] hexDigits = {"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"};

    /**
     * 用SHA-1加密数据
     * @param data      原始数据
     * @return byte[]   加密后数据
     * @throws Exception
     */
    public static byte[] encrypt(byte[] data) throws Exception {

        //MessageDigest为应用程序提供信息摘要算法的功能，如MD5和SHA
        MessageDigest sha = MessageDigest.getInstance(KEY_SHA_1);

        //使用指定的字节数组更新摘要
        sha.update(data);

        //完成摘要Hash计算，调用此方法后，摘要被重置
        return sha.digest();

    }

    /**
     * 用SHA-1加密数据
     * @param data      原始数据
     * @return String   加密后数据
     * @throws Exception
     */
    public static String encrypt(String data) throws Exception {

        //验证传入参数，如果为空直接返回
        if (data == null || "".equals(data)) {
            return "";
        }

        //MessageDigest为应用程序提供信息摘要算法的功能，如MD5和SHA
        MessageDigest sha = MessageDigest.getInstance(KEY_SHA_1);

        //使用指定的字节数组更新摘要
        sha.update(data.getBytes());

        //完成摘要Hash计算，调用此方法后，摘要被重置
        byte[] bytes = sha.digest();

        //将摘要变成十六进制字符串返回
        return byteArrayToHexString(bytes);

    }

    /**
     * 将字节转化成十六进制形式的字符串
     * @param b         字节
     * @return String   字符串
     */
    private static String byteToHexString(byte b) {

        int ret = b;

        if (ret < 0) {
            ret += 256;
        }

        int m = ret / 16;
        int n = ret % 16;

        return hexDigits[m] + hexDigits[n];

    }

    /**
     * 将字节数组转化为十六进制形式的字符串
     * @param bytes     字节数组
     * @return String   字符串
     */
    private static String byteArrayToHexString(byte[] bytes) {

        StringBuffer sb = new StringBuffer();

        for (int i = 0; i < bytes.length; i++) {
            sb.append(byteToHexString(bytes[i]));
        }

        return sb.toString();

    }

}
