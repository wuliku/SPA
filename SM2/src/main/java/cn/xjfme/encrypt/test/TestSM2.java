package cn.xjfme.encrypt.test;

import cn.xjfme.encrypt.utils.Util;
import cn.xjfme.encrypt.utils.sm2.SM2EncDecUtils;
import cn.xjfme.encrypt.utils.sm2.SM2KeyVO;
import cn.xjfme.encrypt.utils.sm2.SM2SignVO;
import cn.xjfme.encrypt.utils.sm2.SM2SignVerUtils;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.junit.Test;

import java.io.IOException;

import static cn.xjfme.encrypt.test.SecurityTestAll.SM2Enc;
import static cn.xjfme.encrypt.test.SecurityTestAll.SM2PubHardKeyHead;

/**
 * @author admin
 * @create 2021-12-26 13:01
 * @
 */
public class TestSM2 {

    @Test
    public void test() throws Exception {
        System.out.println("--产生SM2秘钥--:");
        SM2KeyVO sm2KeyVO = generateSM2Key();
        System.out.println("公钥:" + sm2KeyVO.getPubHexInSoft());
        System.out.println("私钥:" + sm2KeyVO.getPriHexInSoft());

        String src = "I Love You";
        System.out.println("--测试SM2签名--");
        System.out.println("原文hex:" + Util.byteToHex(src.getBytes()));
        String s5 = Util.byteToHex(src.getBytes());

        System.out.println("签名测试开始:");
        SM2SignVO sign = genSM2Signature(sm2KeyVO.getPriHexInSoft(), s5);
        System.out.println("软加密签名结果:" + sign.getSm2_signForSoft());
        System.out.println("加密机签名结果:" + sign.getSm2_signForHard());
        //System.out.println("转签名测试:"+SM2SignHardToSoft(sign.getSm2_signForHard()));
        System.out.println("验签1,软件加密方式:");
        boolean b = verifySM2Signature(sm2KeyVO.getPubHexInSoft(), s5, sign.getSm2_signForSoft());
        System.out.println("软件加密方式验签结果:" + b);
        System.out.println("验签2,硬件加密方式:");
        String sm2_signForHard = sign.getSm2_signForHard();
        System.out.println("签名R:"+sign.sign_r);
        System.out.println("签名S:"+sign.sign_s);
        //System.out.println("硬:"+sm2_signForHard);
        b = verifySM2Signature(sm2KeyVO.getPubHexInSoft(), s5, SM2SignHardToSoft(sign.getSm2_signForHard()));
        System.out.println("硬件加密方式验签结果:" + b);
        if (!b) {
            throw new RuntimeException();
        }
        System.out.println("--签名测试结束--");
    }

    //SM2公钥soft和Hard转换
    public static String SM2PubKeySoftToHard(String softKey) {
        return SM2PubHardKeyHead + softKey;
    }

    //SM2公钥Hard和soft转换
    public static String SM2PubKeyHardToSoft(String hardKey) {
        return hardKey.replaceFirst(SM2PubHardKeyHead, "");
    }

    //产生非对称秘钥
    public static SM2KeyVO generateSM2Key() throws IOException {
        SM2KeyVO sm2KeyVO = SM2EncDecUtils.generateKeyPair();
        return sm2KeyVO;
    }

    //公钥加密
    public static String SM2Enc(String pubKey, String src) throws IOException {
        String encrypt = SM2EncDecUtils.encrypt(Util.hexStringToBytes(pubKey), src.getBytes());
        //删除04
        encrypt=encrypt.substring(2,encrypt.length());
        return encrypt;
    }

    //私钥解密
    public static String SM2Dec(String priKey, String encryptedData) throws IOException {
        //填充04
        encryptedData="04"+encryptedData;
        byte[] decrypt = SM2EncDecUtils.decrypt(Util.hexStringToBytes(priKey), Util.hexStringToBytes(encryptedData));
        return new String(decrypt);
    }

    //私钥签名,参数二:原串必须是hex!!!!因为是直接用于计算签名的,可能是SM3串,也可能是普通串转Hex
    public static SM2SignVO genSM2Signature(String priKey, String sourceData) throws Exception {
        SM2SignVO sign = SM2SignVerUtils.Sign2SM2(Util.hexToByte(priKey), Util.hexToByte(sourceData));
        return sign;
    }

    //公钥验签,参数二:原串必须是hex!!!!因为是直接用于计算签名的,可能是SM3串,也可能是普通串转Hex
    public static boolean verifySM2Signature(String pubKey, String sourceData, String hardSign) {
        SM2SignVO verify = SM2SignVerUtils.VerifySignSM2(Util.hexStringToBytes(pubKey), Util.hexToByte(sourceData), Util.hexToByte(hardSign));
        return verify.isVerify();
    }

    //SM2签名Hard转soft
    public static String SM2SignHardToSoft(String hardSign) {
        byte[] bytes = Util.hexToByte(hardSign);
        byte[] r = new byte[bytes.length / 2];
        byte[] s = new byte[bytes.length / 2];
        System.arraycopy(bytes, 0, r, 0, bytes.length / 2);
        System.arraycopy(bytes, bytes.length / 2, s, 0, bytes.length / 2);
        ASN1Integer d_r = new ASN1Integer(Util.byteConvertInteger(r));
        ASN1Integer d_s = new ASN1Integer(Util.byteConvertInteger(s));
        ASN1EncodableVector v2 = new ASN1EncodableVector();
        v2.add(d_r);
        v2.add(d_s);
        DERSequence sign = new DERSequence(v2);

        String result = null;
        try {
            result = Util.byteToHex(sign.getEncoded());
        } catch (IOException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
        //SM2加密机转软加密编码格式
        //return SM2SignHardKeyHead+hardSign.substring(0, hardSign.length()/2)+SM2SignHardKeyMid+hardSign.substring(hardSign.length()/2);
        return result;
    }
}
