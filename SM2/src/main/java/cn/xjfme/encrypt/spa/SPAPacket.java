package cn.xjfme.encrypt.spa;

import com.sun.xml.internal.bind.v2.model.core.ID;

/**
 * @author admin
 * @create 2021-12-27 12:35
 * @
 */
public class SPAPacket {
    //随机数
    private long RandomValue;

    //用户名
    private String Username;

    //时间戳
    private String Timestamp;

    //fwknop中的FKO的版本号
    private String FKOVersion;

    //消息的类型：访问的消息或者回传的消息
    private String MessageType;

    //使用Nat访问
    private String NatAccess;

    //服务器的认证
    private String Auth;

    //客户端是否超时，0表示没有超时，1表示超时
    private int ClientTimeOut;

    //使用的加密方式
    private String EncryptionType;

    //使用的摘要类型
    private String DigestType;

    //使用的签名方式
    private String SignatureType;

    //使用的协议是那种TCP/UDP
    private String Protocol;

    //源端口号
    private int SourcePort;

    //目的端口号
    private int DestinationPort;

    //源IP地址
    private String SourceIP;

    //目的IP地址
    private String DestinationIP;

    //SPA包的大小
    private long SPAPacketBytes;

    public SPAPacket() {

    }

    public SPAPacket(long randomValue, String username, String timestamp, String FKOVersion, String messageType, String natAccess, String auth, int clientTimeOut, String encryptionType, String digestType, String signatureType, String protocol, int sourcePort, int destinationPort, String sourceIP, String destinationIP, long SPAPacketBytes) {
        RandomValue = randomValue;
        Username = username;
        Timestamp = timestamp;
        this.FKOVersion = FKOVersion;
        MessageType = messageType;
        NatAccess = natAccess;
        Auth = auth;
        ClientTimeOut = clientTimeOut;
        EncryptionType = encryptionType;
        DigestType = digestType;
        SignatureType = signatureType;
        Protocol = protocol;
        SourcePort = sourcePort;
        DestinationPort = destinationPort;
        SourceIP = sourceIP;
        DestinationIP = destinationIP;
        this.SPAPacketBytes = SPAPacketBytes;
    }

    public long getRandomValue() {
        return RandomValue;
    }

    public void setRandomValue(long randomValue) {
        RandomValue = randomValue;
    }

    public String getUsername() {
        return Username;
    }

    public void setUsername(String username) {
        Username = username;
    }

    public String getTimestamp() {
        return Timestamp;
    }

    public void setTimestamp(String timestamp) {
        Timestamp = timestamp;
    }

    public String getFKOVersion() {
        return FKOVersion;
    }

    public void setFKOVersion(String FKOVersion) {
        this.FKOVersion = FKOVersion;
    }

    public String getMessageType() {
        return MessageType;
    }

    public void setMessageType(String messageType) {
        MessageType = messageType;
    }

    public String getNatAccess() {
        return NatAccess;
    }

    public void setNatAccess(String natAccess) {
        NatAccess = natAccess;
    }

    public String getAuth() {
        return Auth;
    }

    public void setAuth(String auth) {
        Auth = auth;
    }

    public int getClientTimeOut() {
        return ClientTimeOut;
    }

    public void setClientTimeOut(int clientTimeOut) {
        ClientTimeOut = clientTimeOut;
    }

    public String getEncryptionType() {
        return EncryptionType;
    }

    public void setEncryptionType(String encryptionType) {
        EncryptionType = encryptionType;
    }

    public String getDigestType() {
        return DigestType;
    }

    public void setDigestType(String digestType) {
        DigestType = digestType;
    }

    public String getSignatureType() {
        return SignatureType;
    }

    public void setSignatureType(String signatureType) {
        SignatureType = signatureType;
    }

    public String getProtocol() {
        return Protocol;
    }

    public void setProtocol(String protocol) {
        Protocol = protocol;
    }

    public int getSourcePort() {
        return SourcePort;
    }

    public void setSourcePort(int sourcePort) {
        SourcePort = sourcePort;
    }

    public int getDestinationPort() {
        return DestinationPort;
    }

    public void setDestinationPort(int destinationPort) {
        DestinationPort = destinationPort;
    }

    public String getSourceIP() {
        return SourceIP;
    }

    public void setSourceIP(String sourceIP) {
        SourceIP = sourceIP;
    }

    public String getDestinationIP() {
        return DestinationIP;
    }

    public void setDestinationIP(String destinationIP) {
        DestinationIP = destinationIP;
    }

    public long getSPAPacketBytes() {
        return SPAPacketBytes;
    }

    public void setSPAPacketBytes(long SPAPacketBytes) {
        this.SPAPacketBytes = SPAPacketBytes;
    }

    @Override
    public String toString() {
        return "SPAPacket{" +
                "RandomValue=" + RandomValue +
                ", Username='" + Username + '\'' +
                ", Timestamp='" + Timestamp + '\'' +
                ", FKOVersion='" + FKOVersion + '\'' +
                ", MessageType='" + MessageType + '\'' +
                ", NatAccess='" + NatAccess + '\'' +
                ", Auth='" + Auth + '\'' +
                ", ClientTimeOut='" + ClientTimeOut + '\'' +
                ", EncryptionType='" + EncryptionType + '\'' +
                ", DigestType='" + DigestType + '\'' +
                ", SignatureType='" + SignatureType + '\'' +
                ", Protocol='" + Protocol + '\'' +
                ", SourcePort=" + SourcePort +
                ", DestinationPort=" + DestinationPort +
                ", SourceIP='" + SourceIP + '\'' +
                ", DestinationIP='" + DestinationIP + '\'' +
                ", SPAPacketBytes=" + SPAPacketBytes +
                '}';
    }
}
