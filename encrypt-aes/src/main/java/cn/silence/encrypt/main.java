package cn.silence.encrypt;

/**
 * Created by Silence on 2017/12/19.
 */
public class main {

    public static void main(String[] args) throws Exception {

        byte[] result = AESCoder.encrypt("测试", "123");

        System.out.println(new String(result));

        result = AESCoder.decrypt(result, "123");

        System.out.println(new String(result));

    }

}
