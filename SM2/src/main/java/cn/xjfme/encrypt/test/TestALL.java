package cn.xjfme.encrypt.test;

import cn.xjfme.encrypt.utils.Util;
import cn.xjfme.encrypt.utils.sm4.SM4Utils;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

/**
 * @author admin
 * @create 2021-12-21 13:49
 * @
 */
public class TestALL {
    @Test
    public void test(){
        //客户端加密的过程
        //生成SPA数据包，将SPA数据包封装成为一个JSON字符串或者一个对象，作为plainText
        String plainText = "哈哈哈哈哈哈哈！";
        byte[] plainBytes = plainText.getBytes();
        String s = Util.byteToHex(plainBytes);
        System.out.println("原文：" + plainText);
        System.out.println("原文转字节：" + s);
        SM4Utils sm4 = new SM4Utils();

        sm4.secretKey = "E76E9B4E0245BC56FCE4E29B208C6A50";
        sm4.hexString = true;
        String cipherText = sm4.encryptData_ECB(plainText);

        System.out.println("密文: " + cipherText);

        byte[] md = new byte[32];
        SM3Digest sm3 = new SM3Digest();
        sm3.update(plainBytes, 0, plainBytes.length);
        sm3.doFinal(md, 0);
        String Hmac1 = new String(Hex.encode(md));
        System.out.println("消息摘要256位：" + Hmac1.toUpperCase());

        //服务器解密的过程
        String decryptPlainText = sm4.decryptData_ECB(cipherText);
        System.out.println("明文: " + decryptPlainText);
        byte[] md2 = new byte[32];
        byte[] decryptPlainBytes = decryptPlainText.getBytes();
        sm3.update(decryptPlainBytes, 0, decryptPlainBytes.length);
        sm3.doFinal(md2, 0);
        String Hmac2 = new String(Hex.encode(md2));
        System.out.println("消息摘要256位：" + Hmac2.toUpperCase());

        if(Hmac1.equals(Hmac2)){
            System.out.println("客户端属于合法用户，且发送的SPA数据包没有被篡改");
        }else{
            System.out.println("客户端是非法用户，拒绝登录");
        }
    }
}
