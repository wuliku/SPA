package cn.xjfme.encrypt.test;

import cn.xjfme.encrypt.utils.Util;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import java.util.Locale;

/**
 * @author admin
 * @create 2021-12-20 19:55
 * @
 */
public class TestSM3 {
    String str = "中国你好";
    String SM3MAC = "";
    String SM2MAC2 = "";
    @Test
    public void sm3() {
        byte[] strBytes = str.getBytes();
        System.out.println(Util.byteToHex(strBytes));
        byte[] md = new byte[32];

        SM3Digest sm3 = new SM3Digest();
        sm3.update(strBytes, 0, strBytes.length);
        sm3.doFinal(md, 0);
        String s = new String(Hex.encode(md));
        SM3MAC = s.toUpperCase();
        System.out.println("原SPA的消息摘要：" + SM3MAC);


        String str = "中国你好";
        byte[] strBytes1 = str.getBytes();
        System.out.println(Util.byteToHex(strBytes1));
        byte[] md1 = new byte[32];

        SM3Digest sm32 = new SM3Digest();
        sm32.update(strBytes1, 0, strBytes.length);
        sm32.doFinal(md1, 0);
        String s2 = new String(Hex.encode(md));
        SM2MAC2 = s2.toUpperCase();
        System.out.println("重新计算SPA的消息摘要：" + SM2MAC2);
        System.out.println(SM2MAC2.equals(SM3MAC));
    }

}
