package cn.xjfme.encrypt.test;

import cn.xjfme.encrypt.utils.Util;
import cn.xjfme.encrypt.utils.sm4.SM4Utils;
import org.junit.Test;

import java.io.IOException;

/**
 * @author admin
 * @create 2021-12-20 19:59
 * @
 */
public class TestSM4 {


    @Test
    public void sm4() throws IOException {
        String plainText = "哈哈哈哈哈哈哈！";
        String s = Util.byteToHex(plainText.getBytes());
        System.out.println("原文：" + s);
        SM4Utils sm4 = new SM4Utils();

        sm4.secretKey = "E76E9B4E0245BC56FCE4E29B208C6A50";
        sm4.hexString = true;
        System.out.println("ECB模式加密");
        String cipherText = sm4.encryptData_ECB(plainText);

        System.out.println("密文: " + cipherText);

        plainText = sm4.decryptData_ECB(cipherText);
        System.out.println("明文: " + plainText);
        System.out.println("============");





        System.out.println("CBC模式加密");
        sm4.iv = "30303030303030303030303030303033";
        cipherText = sm4.encryptData_CBC(plainText);
        System.out.println("加密密文: " + cipherText);
        System.out.println("================");

        plainText = sm4.decryptData_CBC(cipherText);
        System.out.println("解密明文: " + plainText);

    }
}
