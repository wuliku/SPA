package cn.xjfme.encrypt.spa;

import cn.xjfme.encrypt.utils.Util;
import cn.xjfme.encrypt.utils.sm2.SM2EncDecUtils;
import cn.xjfme.encrypt.utils.sm2.SM2KeyVO;
import cn.xjfme.encrypt.utils.sm2.SM2SignVO;
import cn.xjfme.encrypt.utils.sm2.SM2SignVerUtils;
import cn.xjfme.encrypt.utils.sm4.SM4Utils;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import static cn.xjfme.encrypt.test.SecurityTestAll.SM2PubHardKeyHead;

/**
 * @author admin
 * @create 2021-12-27 14:00
 * @
 */
public class AuthSPAPacket {
    //客户端的公钥
    static String PK = "048dc67da86b2e5b986b5964da513cbe4682107dc2344c049e538472a354272120481ef950d3a66d5be2bbffa404c7b27ca808fc3bda5050706c1ea9483856ffa5";
    public static void main(String[] args) throws Exception {
        //执行客户端生成的信息，
        Map<String, String> AuthHashMap = GenerSPA.getSPAHashMap();
        String spaJson = AuthHashMap.get("SPAJson");
        String cipherText = AuthHashMap.get("密文");
        String SM3MAC = AuthHashMap.get("摘要");
        String sign1 = AuthHashMap.get("签名1");
        String sign2 = AuthHashMap.get("签名2");

        System.out.println("-----------------零信任网关执行操作--------------");
        //第一步验证客户端的额签名是否正确
        System.out.println("第一步开始验证签名信息：");
        String s5 = Util.byteToHex(spaJson.getBytes());
        System.out.println("验签1,软件加密方式:");
        boolean b = verifySM2Signature(PK, s5, sign1);
        System.out.println("软件加密方式验签结果:" + b);
        System.out.println("验签2,硬件加密方式:");
        b = verifySM2Signature(PK, s5, SM2SignHardToSoft(sign2));
        System.out.println("硬件加密方式验签结果:" + b);
        System.out.println("--签名测试结束--");
        System.out.println();

        //第二步解密客户端的加密单包信息
        System.out.println("第二步解密客户端的加密单包信息");
        SM4Utils sm4 = new SM4Utils();
        sm4.secretKey = "E76E9B4E0245BC56FCE4E29B208C6A50";
        sm4.hexString = true;
        String plainText = sm4.decryptData_ECB(cipherText);
        System.out.println("SPA密文：" + cipherText);
        System.out.println("解密结果: " + plainText);
        System.out.println();

        //第三步验证客户端的摘要信息
        System.out.println("第三步验证客户端的摘要信息");
        byte[] strBytes = plainText.getBytes();
        byte[] md = new byte[32];
        SM3Digest sm3 = new SM3Digest();
        sm3.update(strBytes, 0, strBytes.length);
        sm3.doFinal(md, 0);
        String s = new String(Hex.encode(md));
        String SM3MAC2 = s.toUpperCase();
        System.out.println("客户端发送的单包信息摘要结果：" + SM3MAC);
        System.out.println("零信任网关自己计算的单包信息的摘要结果为：" + SM3MAC2);
        if(SM3MAC.equals(SM3MAC2)){
            System.out.println("SM3摘要结果一致，验证成功");
        }else{
            System.out.println("校验失败");
        }
        System.out.println();

        //第四步，验证SPA数据包中的信息
        System.out.println("第四步，验证SPA数据包中的信息");
        //将JSON转化为Map
        //可以用来解析JSON文件，可以通过readvalue方法将json反序列化为一个对象或者集合
        ObjectMapper mapper = new ObjectMapper();
        //用于指定反序列化的类型 HashMap<String, Object>
        TypeReference<HashMap<String, Object>> type =
                new TypeReference<HashMap<String, Object>>() {};

        HashMap<String, Object> j1 = mapper.readValue(plainText,type);
        System.out.println("输出单包数据信息：");
        Iterator<Map.Entry<String, Object>> iterator = j1.entrySet().iterator();
        while (iterator.hasNext()){
            Map.Entry<String, Object> next = iterator.next();
            System.out.println(next.getKey() + ": " + next.getValue());
        }
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
