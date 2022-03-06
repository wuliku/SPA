package cn.xjfme.encrypt.spa;

import cn.xjfme.encrypt.utils.Util;
import cn.xjfme.encrypt.utils.sm2.SM2EncDecUtils;
import cn.xjfme.encrypt.utils.sm2.SM2KeyVO;
import cn.xjfme.encrypt.utils.sm2.SM2SignVO;
import cn.xjfme.encrypt.utils.sm2.SM2SignVerUtils;
import cn.xjfme.encrypt.utils.sm4.SM4Utils;
import com.alibaba.fastjson.JSONArray;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;

import static cn.xjfme.encrypt.test.SecurityTestAll.SM2PubHardKeyHead;

/**
 * @author admin
 * @create 2021-12-27 13:22
 * @
 */
public class GenerSPA {
    //定义单包信息（JSON）、加密的信息、摘要信息、签名信息；
    static Map<String, String> SPAHashMap = new HashMap<>();

    public static void main(String[] args) throws Exception {
        GenSPAPacket();
    }

    public static void GenSPAPacket() throws Exception {
        System.out.println("-----------------客户端执行操作--------------");
        //第一步：生成SPA数据包
        System.out.println("第一步：生成SPA数据包");
        SPAPacket spaPacket = new SPAPacket();
        //生成随机数
        long RandomValue = (long) (Math.random() * 1000000000 + 1);
        spaPacket.setRandomValue(RandomValue);

        //生成用户名
        spaPacket.setUsername("马春亮");

        //生成时间戳
        LocalDateTime now = LocalDateTime.now();
        String Timestamp = now.format(DateTimeFormatter.ofPattern("yyyyMMddHHmmssSSS"));
        spaPacket.setTimestamp(Timestamp);

        //生成fwknop中的FKO的版本号
        String FKOVersion = "3.0.0";
        spaPacket.setFKOVersion(FKOVersion);

        //生成消息的访问类型
        String MessageType = "Access message";
        spaPacket.setMessageType(MessageType);

        //是否有NAT访问
        spaPacket.setNatAccess("NO");

        //服务器认证
        spaPacket.setAuth("YES");

        //客户端是否超时，0表示没有超时，1表示超时
        spaPacket.setClientTimeOut(0);

        //设置加密的方式
        spaPacket.setEncryptionType("SM4");

        //设置摘要类型
        spaPacket.setDigestType("SM3");

        //设置签名方式
        spaPacket.setSignatureType("SM2");

        //设置协议是类型
        spaPacket.setProtocol("UDP");

        //设置源端口号
        spaPacket.setSourcePort(65652);

        //设置目的端口号
        spaPacket.setDestinationPort(22);

        //设置源IP地址
        spaPacket.setSourceIP("192.168.231.128");

        //设置目的IP地址
        spaPacket.setDestinationIP("192.168.231.131");

        //设置SPA包的大小
        spaPacket.setSPAPacketBytes(225);
        //输出单包认证信息
        System.out.println(spaPacket);
        System.out.println();



        //第二步对SPA数据包进行加密，先将spaPacket对象转为JSON字符串
        System.out.println("第二步对SPA数据包进行加密，先将spaPacket对象转为JSON字符串");
        Object obj = JSONArray.toJSON(spaPacket);
        String json = obj.toString();
        System.out.println("将spaPacket对象转成json:");
        System.out.println(json);
        SPAHashMap.put("SPAJson", json);

        //加密
        SM4Utils sm4 = new SM4Utils();
        sm4.secretKey = "E76E9B4E0245BC56FCE4E29B208C6A50";
        sm4.hexString = true;
        System.out.println("ECB模式加密");
        String cipherText = sm4.encryptData_ECB(json);
        System.out.println("密文: " + cipherText);
        System.out.println();
        SPAHashMap.put("密文", cipherText);

        //第三步计算spaPacket的消息摘要
        System.out.println("第三步计算spaPacket的消息摘要");
        byte[] strBytes = json.getBytes();
        byte[] md = new byte[32];
        SM3Digest sm3 = new SM3Digest();
        sm3.update(strBytes, 0, strBytes.length);
        sm3.doFinal(md, 0);
        String s = new String(Hex.encode(md));
        String SM3MAC = s.toUpperCase();
        System.out.println("单包信息的摘要结果为：" + SM3MAC);
        System.out.println();
        SPAHashMap.put("摘要", SM3MAC);

        //第四步客户端对单包信息进行签名
        System.out.println("第四步客户端对单包信息进行签名");
        System.out.println("--产生SM2秘钥--:");
        String PK = "048dc67da86b2e5b986b5964da513cbe4682107dc2344c049e538472a354272120481ef950d3a66d5be2bbffa404c7b27ca808fc3bda5050706c1ea9483856ffa5";
        String SK = "3282a5bf02d839b481aacb371758673c736a4c87c46805f9ad4655a1e2c2b066";
        System.out.println("公钥:" + PK);
        System.out.println("私钥:" + SK);

        //获取json的字节文件
        String s5 = Util.byteToHex(json.getBytes());

        System.out.println("签名测试开始:");
        SM2SignVO sign = genSM2Signature(SK, s5);
        System.out.println("软加密签名结果:" + sign.getSm2_signForSoft());
        System.out.println("加密机签名结果:" + sign.getSm2_signForHard());
        System.out.println();

        SPAHashMap.put("签名1", sign.getSm2_signForSoft());
        SPAHashMap.put("签名2", sign.getSm2_signForHard());


    }

    public static Map<String,String> getSPAHashMap() throws Exception {
        GenSPAPacket();
        return SPAHashMap;
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
