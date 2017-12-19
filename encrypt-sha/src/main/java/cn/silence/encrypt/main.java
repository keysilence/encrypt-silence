package cn.silence.encrypt;

/**
 * Created by Silence on 2017/12/18.
 */
public class main {

    public static void main(String[] args) throws Exception {

        String result = SHACoder.encrypt("测试");

        System.out.println(result);

    }

}
