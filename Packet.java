package jmento;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;

/**
 * The class Packet is defined to construct the packet to be sended.
 * Generally, several types of packet is used:
 * <ul>
 * <li>Start Packet</li>
 * <li>Identity Packet</li>
 * <li>Challenge Packet</li>
 * <li>Echo Packet</li>
 * <li>Logoff Packet</li>
 * </ul>
 * So the methods in the class are corresponding to these packets.
 */
public class Packet {

    private static final byte[] RUIJIE_ADDR = 
    {(byte)0x01,(byte)0xD0,(byte)0xF8,(byte)0x00,(byte)0x00,(byte)0x03}; 

    private static final byte[] FILLBUF = {
	(byte)00, (byte)00, (byte)13, (byte)11, (byte)38, (byte)30, (byte)32, (byte)31,
	(byte)78, (byte)2e, (byte)65, (byte)78, (byte)65, (byte)00, (byte)00, (byte)00,
	(byte)00, (byte)00, (byte)00, (byte)00, (byte)00, (byte)00, (byte)00, (byte)00,
	(byte)00, (byte)00, (byte)00, (byte)00, (byte)00, (byte)00, (byte)00, (byte)00,
	(byte)00, (byte)00, (byte)00, (byte)00, (byte)04, (byte)49, (byte)03, (byte)02,
	(byte)00, (byte)00, (byte)00, (byte)13, (byte)11, (byte)01, (byte)cf, (byte)1a,
	(byte)28, (byte)00, (byte)00, (byte)13, (byte)11, (byte)17, (byte)22, (byte)32,
	(byte)45, (byte)41, (byte)38, (byte)33, (byte)38, (byte)31, (byte)36, (byte)35,
	(byte)37, (byte)42, (byte)31, (byte)33, (byte)42, (byte)32, (byte)31, (byte)32,
	(byte)38, (byte)33, (byte)42, (byte)34, (byte)43, (byte)34, (byte)36, (byte)42,
	(byte)36, (byte)33, (byte)38, (byte)38, (byte)34, (byte)39, (byte)38, (byte)1a,
	(byte)0c, (byte)00, (byte)00, (byte)13, (byte)11, (byte)18, (byte)06, (byte)00,
	(byte)00, (byte)00, (byte)01, (byte)1a, (byte)0e, (byte)00, (byte)00, (byte)13,
	(byte)11, (byte)2d, (byte)08, (byte)e4, (byte)11, (byte)5b, (byte)54, (byte)5d,
	(byte)36, (byte)1a, (byte)08, (byte)00, (byte)00, (byte)13, (byte)11, (byte)2f,
	(byte)02, (byte)1a, (byte)09, (byte)00, (byte)00, (byte)13, (byte)11, (byte)35,
	(byte)03, (byte)03, (byte)1a, (byte)18, (byte)00, (byte)00, (byte)13, (byte)11,
	(byte)36, (byte)12, (byte)fe, (byte)80, (byte)00, (byte)00, (byte)00, (byte)00,
	(byte)00, (byte)00, (byte)5a, (byte)66, (byte)ba, (byte)ff, (byte)fe, (byte)de,
	(byte)2d, (byte)8d, (byte)1a, (byte)18, (byte)00, (byte)00, (byte)13, (byte)11,
	(byte)38, (byte)12, (byte)fe, (byte)80, (byte)00, (byte)00, (byte)00, (byte)00,
	(byte)00, (byte)00, (byte)e9, (byte)52, (byte)96, (byte)4d, (byte)ae, (byte)cc,
	(byte)74, (byte)23, (byte)1a, (byte)18, (byte)00, (byte)00, (byte)13, (byte)11,
	(byte)4e, (byte)12, (byte)20, (byte)01, (byte)02, (byte)50, (byte)40, (byte)00,
	(byte)80, (byte)00, (byte)e9, (byte)52, (byte)96, (byte)4d, (byte)ae, (byte)cc,
	(byte)74, (byte)23, (byte)1a, (byte)88, (byte)00, (byte)00, (byte)13, (byte)11,
	(byte)4d, (byte)82, (byte)34, (byte)66, (byte)39, (byte)66, (byte)61, (byte)34,
	(byte)38, (byte)39, (byte)36, (byte)30, (byte)31, (byte)33, (byte)61, (byte)32,
	(byte)39, (byte)66, (byte)37, (byte)64, (byte)65, (byte)65, (byte)64, (byte)63,
	(byte)35, (byte)63, (byte)31, (byte)38, (byte)64, (byte)31, (byte)38, (byte)35,
	(byte)34, (byte)34, (byte)65, (byte)33, (byte)63, (byte)65, (byte)64, (byte)38,
	(byte)32, (byte)38, (byte)61, (byte)61, (byte)30, (byte)35, (byte)66, (byte)61,
	(byte)63, (byte)62, (byte)38, (byte)37, (byte)33, (byte)36, (byte)31, (byte)65,
	(byte)65, (byte)38, (byte)64, (byte)37, (byte)32, (byte)31, (byte)63, (byte)63,
	(byte)38, (byte)38, (byte)34, (byte)64, (byte)66, (byte)63, (byte)32, (byte)64,
	(byte)61, (byte)64, (byte)62, (byte)39, (byte)61, (byte)66, (byte)33, (byte)35,
	(byte)66, (byte)36, (byte)31, (byte)62, (byte)35, (byte)36, (byte)33, (byte)38,
	(byte)31, (byte)64, (byte)34, (byte)63, (byte)30, (byte)63, (byte)36, (byte)62,
	(byte)61, (byte)39, (byte)35, (byte)31, (byte)35, (byte)61, (byte)35, (byte)39,
	(byte)37, (byte)33, (byte)65, (byte)31, (byte)63, (byte)62, (byte)63, (byte)64,
	(byte)65, (byte)33, (byte)38, (byte)36, (byte)34, (byte)37, (byte)62, (byte)31,
	(byte)39, (byte)36, (byte)34, (byte)37, (byte)31, (byte)65, (byte)34, (byte)33,
	(byte)62, (byte)62, (byte)1a, (byte)28, (byte)00, (byte)00, (byte)13, (byte)11,
	(byte)39, (byte)22, (byte)69, (byte)6e, (byte)74, (byte)65, (byte)72, (byte)6e,
	(byte)65, (byte)74, (byte)00, (byte)00, (byte)00, (byte)00, (byte)00, (byte)00,
	(byte)00, (byte)00, (byte)00, (byte)00, (byte)00, (byte)00, (byte)00, (byte)00,
	(byte)00, (byte)00, (byte)00, (byte)00, (byte)00, (byte)00, (byte)00, (byte)00,
	(byte)00, (byte)00, (byte)1a, (byte)48, (byte)00, (byte)00, (byte)13, (byte)11,
	(byte)54, (byte)42, (byte)53, (byte)32, (byte)57, (byte)47, (byte)32, (byte)54,
	(byte)48, (byte)38, (byte)00, (byte)00, (byte)00, (byte)00, (byte)00, (byte)00,
	(byte)00, (byte)00, (byte)00, (byte)00, (byte)00, (byte)00, (byte)00, (byte)00,
	(byte)00, (byte)00, (byte)00, (byte)00, (byte)00, (byte)00, (byte)00, (byte)00,
	(byte)00, (byte)00, (byte)00, (byte)00, (byte)00, (byte)00, (byte)00, (byte)00,
	(byte)00, (byte)00, (byte)00, (byte)00, (byte)00, (byte)00, (byte)00, (byte)00,
	(byte)00, (byte)00, (byte)00, (byte)00, (byte)00, (byte)00, (byte)00, (byte)00,
	(byte)00, (byte)00, (byte)00, (byte)00, (byte)00, (byte)00, (byte)00, (byte)00,
	(byte)00, (byte)00, (byte)1a, (byte)08, (byte)00, (byte)00, (byte)13, (byte)11,
	(byte)55, (byte)02, (byte)1a, (byte)09, (byte)00, (byte)00, (byte)13, (byte)11,
	(byte)62, (byte)03, (byte)00, (byte)1a, (byte)09, (byte)00, (byte)00, (byte)13,
	(byte)11, (byte)6b, (byte)03, (byte)00, (byte)1a, (byte)09, (byte)00, (byte)00,
	(byte)13, (byte)11, (byte)70, (byte)03, (byte)40, (byte)1a, (byte)19, (byte)00,
	(byte)00, (byte)13, (byte)11, (byte)6f, (byte)13, (byte)52, (byte)47, (byte)2d,
	(byte)53, (byte)55, (byte)20, (byte)56, (byte)34, (byte)2e, (byte)37, (byte)33,
	(byte)2d, (byte)30, (byte)36, (byte)31, (byte)34, (byte)00,
    };

    protected byte[] destMac;
    protected byte[] localMac;

    // The first 23 bytes of the EAP-packet are actually
    // some info enscrypted using the mysterious checksum()
    protected byte[] info;

    // There is a remaining fill buffer, containing mainly
    // the information about the 8021x.exe and so on
    // This is where the most tricky buf
    protected byte[] fillBuf;

    // The EAP frame used to be sent
    protected ByteBuffer frame;

    // The configration
    Config conf;

    Packet(String confPath) {
        conf = new Config(confPath);
        
        try {
            getMac(conf.nic);
        } catch (IOException e) {
            e.printStackTrace();
            return;
        }
        
        destMac = RUIJIE_ADDR;
        
        // Initialize the frame to be 800 bytes
        // According to the packets captured,
        // the non-zero bits don't exceed 600 bytes
        frame = ByteBuffer.allocate(800);
        
        buildInfo();

        buildFillBuf();
    }

    protected void buildStart() {
        clearFrame();

        fillHeader();
        // The Packet type is 0x01: EAPoL-Start
        frame.put((byte)0x01);
    	// The length can just leave to be 00 00
    	frame.put(new byte[]{0x00, 0x00});
        // Fill in the information
        frame.put(info);
        frame.put(fillBuf);

        // Always flip before sending
        frame.flip();
    }

    protected void buildIdentity(byte ID) {
        clearFrame();

        fillHeader();
        // The Packet type is 0x00: EAP-Packet
        frame.put((byte)0x00);
        byte[] nameLen = new byte[2];
        nameLen[1] = (byte)(conf.username.length + 5);
        nameLen[0] = (byte)((conf.username.length + 5) >>> 8);
        frame.put(nameLen);
        // The code for response is 0x02
        frame.put((byte)0x02);
        // The ID byte, from the captured request for Identity packet
        frame.put(ID);
        frame.put(nameLen);
        // The code for Identity is 0x01
        frame.put((byte)0x01);
        frame.put(conf.username);
        frame.put(info);
        frame.put(fillBuf);

        frame.flip();
    }

    protected void buildChallenge(byte ID, byte[] salt) {
        clearFrame();

        fillHeader();
        // The Packet type is 0x00: EAP-Packet
        frame.put((byte)0x00);
        byte[] nameLen = new byte[2];
        nameLen[1] = (byte)(conf.username.length + 22);
        nameLen[0] = (byte)((conf.username.length + 22) >>> 8);
        frame.put(nameLen);
        // The code for response is 0x02
        frame.put((byte)0x02);
        // The ID byte, from the captured request for Challenge packet
        frame.put(ID);
        frame.put(nameLen);
        // The code for MD5-Challenge is 0x04
        frame.put((byte)0x04);
        // The value-size is 0x10
        frame.put((byte)0x10);

        // The data used for md5 hash sequencely :
        // ID, password, salt
        byte[] passwdData = new byte[1 + salt.length + conf.password.length];
        byte[] sendPasswd;
        
        passwdData[0] = ID;
        System.arraycopy(conf.password, 0, passwdData, 1, conf.password.length);
        System.arraycopy(salt, 0, passwdData, 1+conf.password.length, salt.length);
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(passwdData);
            sendPasswd = md.digest();
        } catch (NoSuchAlgorithmException e) {
            System.err.println("No such algorithm!");
            return;
        }
        frame.put(sendPasswd);
        frame.put(conf.username);
        frame.put(info);
        frame.put(fillBuf);

        frame.flip();
    }

    /**
     * The packet to maintain online status
     */
    protected void buildEcho(byte[] echoKey, byte[] echoNo) {
        clearFrame();

        fillHeader();
        // Mysterious type 0xbf: Unknown
        frame.put((byte)0xbf);
        // The length area if always 0x00 0x1e
        frame.put(new byte[]{0x00, 0x1e});
        // There are actually only 4 bytes different in everty echo packet
        final byte[] first = new byte[]{(byte)0xff, (byte)0xff, (byte)0x37, 
					(byte)0x77, (byte)0x7f, (byte)0x9f};
        frame.put(first);
        // The 4-bytes echo key has to be determined by the captured buffer
        frame.put(echoKey);
        frame.put(first);
        frame.put(echoNo);
        byte[] last = new byte[]{(byte)0xff, (byte)0xff, (byte)0x37, 
				 (byte)0x77, (byte)0x7f, (byte)0x3f, (byte)0xff};
        frame.put(last);

        frame.flip();
    }

    /**
     * The logoff packet is pretty much the same as the start packet
     * except for the code area in the header
     */
    protected void buildLogoff() {
        clearFrame();
        fillHeader();
        // The type for logoff is 0x02
        frame.put((byte)0x02);
        // The length area can be left to be zero
        frame.put(new byte[]{0x00, 0x00});
        frame.put(info);
        frame.put(fillBuf);

        frame.flip();
    }

    private void buildFillBuf() {
        fillBuf = FILLBUF;
        setProperty(PROP_DHCP, new byte[]{0x00});
        setProperty(PROP_MAC, localMac);
        System.arraycopy(conf.version, 0, fillBuf, 0x24, 2);
    }

    // Type 0x18 for dhcp
    // Type 0x2D for local MAC address
    // Another mysterious algorithm
    // the start packet contains some machine-dependent code
    // and it's hard to determine exactly what are they
    // So you might have to capture your own packet
    
    private final int PROP_DHCP = 0x18;
    private final int PROP_MAC  = 0x2D;
    
    private void setProperty(int type, byte[] value) {

        int p = 0x2F;
        int end = fillBuf.length - value.length - 8;
        while (p < end) {
            if (fillBuf[p] == 0x1a) 
                p += 2;
            if (fillBuf[p + 4] == type) {
		System.arraycopy(value, 0, fillBuf, 
				 p + 4 +
				 ((fillBuf[p+5] < 0) ? fillBuf[p+5] + 256 : fillBuf[p+5])
				 - value.length, value.length);
		return;
            }
	    p += ((fillBuf[p+5] < 0) ? fillBuf[p+5] + 256 : fillBuf[p+5]) + 4;
        }
    }

    /**
     * Get the MAC address of the device `name'
     */
    private void getMac(String name) throws IOException {
        List<PcapIf> allDevs = new ArrayList<PcapIf>();
        StringBuilder errBuf = new StringBuilder();

        int r = Pcap.findAllDevs(allDevs, errBuf);
        if (r == Pcap.NOT_OK || allDevs.isEmpty()) {
            System.err.printf("Can't access devices (permission denied?): %s\n", 
			      errBuf.toString());
            return;
        }

        for (PcapIf p : allDevs) {
            if (p.getName().equals(name)) {
                localMac = p.getHardwareAddress();
		return;
            }
        }
        System.err.printf("Can't find device: %s, wrong name?\n", name);
    }

    /**
     * Fill in the header, that is the first 15 bytes of the frame
     */
    private void fillHeader() {
        frame.put(destMac);
        frame.put(localMac);
        // The type for EAPol is 0x888e
        final byte[] ethernetType = 
            new byte[]{(byte)0x88, (byte)0x8e};
        frame.put(ethernetType);
        // The version of EAPol is currently 0x01
        frame.put((byte)0x01);
    }

    private void clearFrame() {
        byte[] allZero = new byte[800];
        frame.clear();
        frame.put(allZero);
        frame.clear();
    }

    // Used to perform unsigned xor on byte
    private static int xor(byte a, byte b) {
        return ((a < 0) ? (a + 256) : a) ^ ((b < 0) ? (b + 256) : b);
    }

    /**
     * Ruijie Algorithm
     * Reverse the bits in a byte and take inverse.
     */
    // Single byte version
    protected byte encode(byte b) {
        return (byte)(~(Integer.reverse(b)) >>> (Integer.SIZE - Byte.SIZE));
    }

    // Byte array version
    protected byte[] encode(byte[] B) {
        for (int i = 0; i < B.length; ++i) {
            B[i] = encode(B[i]);
        }
        return B;
    }

    /**
     * Ruijie Algorithm
     * This one is actually mysterious, with a total of 23 bytes
     * The first 21 bytes are some information such as IP 
     * the ending two bytes are the checksum
     * the whole frame is encoded
     */
    private void buildInfo() {
        final byte[] table = {
            (byte)0x00,(byte)0x00,(byte)0x21,(byte)0x10,(byte)0x42,(byte)0x20,(byte)0x63,(byte)0x30,
            (byte)0x84,(byte)0x40,(byte)0xA5,(byte)0x50,(byte)0xC6,(byte)0x60,(byte)0xE7,(byte)0x70,
            (byte)0x08,(byte)0x81,(byte)0x29,(byte)0x91,(byte)0x4A,(byte)0xA1,(byte)0x6B,(byte)0xB1,
            (byte)0x8C,(byte)0xC1,(byte)0xAD,(byte)0xD1,(byte)0xCE,(byte)0xE1,(byte)0xEF,(byte)0xF1,
            (byte)0x31,(byte)0x12,(byte)0x10,(byte)0x02,(byte)0x73,(byte)0x32,(byte)0x52,(byte)0x22,
            (byte)0xB5,(byte)0x52,(byte)0x94,(byte)0x42,(byte)0xF7,(byte)0x72,(byte)0xD6,(byte)0x62,
            (byte)0x39,(byte)0x93,(byte)0x18,(byte)0x83,(byte)0x7B,(byte)0xB3,(byte)0x5A,(byte)0xA3,
            (byte)0xBD,(byte)0xD3,(byte)0x9C,(byte)0xC3,(byte)0xFF,(byte)0xF3,(byte)0xDE,(byte)0xE3,
            (byte)0x62,(byte)0x24,(byte)0x43,(byte)0x34,(byte)0x20,(byte)0x04,(byte)0x01,(byte)0x14,
            (byte)0xE6,(byte)0x64,(byte)0xC7,(byte)0x74,(byte)0xA4,(byte)0x44,(byte)0x85,(byte)0x54,
            (byte)0x6A,(byte)0xA5,(byte)0x4B,(byte)0xB5,(byte)0x28,(byte)0x85,(byte)0x09,(byte)0x95,
            (byte)0xEE,(byte)0xE5,(byte)0xCF,(byte)0xF5,(byte)0xAC,(byte)0xC5,(byte)0x8D,(byte)0xD5,
            (byte)0x53,(byte)0x36,(byte)0x72,(byte)0x26,(byte)0x11,(byte)0x16,(byte)0x30,(byte)0x06,
            (byte)0xD7,(byte)0x76,(byte)0xF6,(byte)0x66,(byte)0x95,(byte)0x56,(byte)0xB4,(byte)0x46,
            (byte)0x5B,(byte)0xB7,(byte)0x7A,(byte)0xA7,(byte)0x19,(byte)0x97,(byte)0x38,(byte)0x87,
            (byte)0xDF,(byte)0xF7,(byte)0xFE,(byte)0xE7,(byte)0x9D,(byte)0xD7,(byte)0xBC,(byte)0xC7,
            (byte)0xC4,(byte)0x48,(byte)0xE5,(byte)0x58,(byte)0x86,(byte)0x68,(byte)0xA7,(byte)0x78,
            (byte)0x40,(byte)0x08,(byte)0x61,(byte)0x18,(byte)0x02,(byte)0x28,(byte)0x23,(byte)0x38,
            (byte)0xCC,(byte)0xC9,(byte)0xED,(byte)0xD9,(byte)0x8E,(byte)0xE9,(byte)0xAF,(byte)0xF9,
            (byte)0x48,(byte)0x89,(byte)0x69,(byte)0x99,(byte)0x0A,(byte)0xA9,(byte)0x2B,(byte)0xB9,
            (byte)0xF5,(byte)0x5A,(byte)0xD4,(byte)0x4A,(byte)0xB7,(byte)0x7A,(byte)0x96,(byte)0x6A,
            (byte)0x71,(byte)0x1A,(byte)0x50,(byte)0x0A,(byte)0x33,(byte)0x3A,(byte)0x12,(byte)0x2A,
            (byte)0xFD,(byte)0xDB,(byte)0xDC,(byte)0xCB,(byte)0xBF,(byte)0xFB,(byte)0x9E,(byte)0xEB,
            (byte)0x79,(byte)0x9B,(byte)0x58,(byte)0x8B,(byte)0x3B,(byte)0xBB,(byte)0x1A,(byte)0xAB,
            (byte)0xA6,(byte)0x6C,(byte)0x87,(byte)0x7C,(byte)0xE4,(byte)0x4C,(byte)0xC5,(byte)0x5C,
            (byte)0x22,(byte)0x2C,(byte)0x03,(byte)0x3C,(byte)0x60,(byte)0x0C,(byte)0x41,(byte)0x1C,
            (byte)0xAE,(byte)0xED,(byte)0x8F,(byte)0xFD,(byte)0xEC,(byte)0xCD,(byte)0xCD,(byte)0xDD,
            (byte)0x2A,(byte)0xAD,(byte)0x0B,(byte)0xBD,(byte)0x68,(byte)0x8D,(byte)0x49,(byte)0x9D,
            (byte)0x97,(byte)0x7E,(byte)0xB6,(byte)0x6E,(byte)0xD5,(byte)0x5E,(byte)0xF4,(byte)0x4E,
            (byte)0x13,(byte)0x3E,(byte)0x32,(byte)0x2E,(byte)0x51,(byte)0x1E,(byte)0x70,(byte)0x0E,
            (byte)0x9F,(byte)0xFF,(byte)0xBE,(byte)0xEF,(byte)0xDD,(byte)0xDF,(byte)0xFC,(byte)0xCF,
            (byte)0x1B,(byte)0xBF,(byte)0x3A,(byte)0xAF,(byte)0x59,(byte)0x9F,(byte)0x78,(byte)0x8F,
            (byte)0x88,(byte)0x91,(byte)0xA9,(byte)0x81,(byte)0xCA,(byte)0xB1,(byte)0xEB,(byte)0xA1,
            (byte)0x0C,(byte)0xD1,(byte)0x2D,(byte)0xC1,(byte)0x4E,(byte)0xF1,(byte)0x6F,(byte)0xE1,
            (byte)0x80,(byte)0x10,(byte)0xA1,(byte)0x00,(byte)0xC2,(byte)0x30,(byte)0xE3,(byte)0x20,
            (byte)0x04,(byte)0x50,(byte)0x25,(byte)0x40,(byte)0x46,(byte)0x70,(byte)0x67,(byte)0x60,
            (byte)0xB9,(byte)0x83,(byte)0x98,(byte)0x93,(byte)0xFB,(byte)0xA3,(byte)0xDA,(byte)0xB3,
            (byte)0x3D,(byte)0xC3,(byte)0x1C,(byte)0xD3,(byte)0x7F,(byte)0xE3,(byte)0x5E,(byte)0xF3,
            (byte)0xB1,(byte)0x02,(byte)0x90,(byte)0x12,(byte)0xF3,(byte)0x22,(byte)0xD2,(byte)0x32,
            (byte)0x35,(byte)0x42,(byte)0x14,(byte)0x52,(byte)0x77,(byte)0x62,(byte)0x56,(byte)0x72,
            (byte)0xEA,(byte)0xB5,(byte)0xCB,(byte)0xA5,(byte)0xA8,(byte)0x95,(byte)0x89,(byte)0x85,
            (byte)0x6E,(byte)0xF5,(byte)0x4F,(byte)0xE5,(byte)0x2C,(byte)0xD5,(byte)0x0D,(byte)0xC5,
            (byte)0xE2,(byte)0x34,(byte)0xC3,(byte)0x24,(byte)0xA0,(byte)0x14,(byte)0x81,(byte)0x04,
            (byte)0x66,(byte)0x74,(byte)0x47,(byte)0x64,(byte)0x24,(byte)0x54,(byte)0x05,(byte)0x44,
            (byte)0xDB,(byte)0xA7,(byte)0xFA,(byte)0xB7,(byte)0x99,(byte)0x87,(byte)0xB8,(byte)0x97,
            (byte)0x5F,(byte)0xE7,(byte)0x7E,(byte)0xF7,(byte)0x1D,(byte)0xC7,(byte)0x3C,(byte)0xD7,
            (byte)0xD3,(byte)0x26,(byte)0xF2,(byte)0x36,(byte)0x91,(byte)0x06,(byte)0xB0,(byte)0x16,
            (byte)0x57,(byte)0x66,(byte)0x76,(byte)0x76,(byte)0x15,(byte)0x46,(byte)0x34,(byte)0x56,
            (byte)0x4C,(byte)0xD9,(byte)0x6D,(byte)0xC9,(byte)0x0E,(byte)0xF9,(byte)0x2F,(byte)0xE9,
            (byte)0xC8,(byte)0x99,(byte)0xE9,(byte)0x89,(byte)0x8A,(byte)0xB9,(byte)0xAB,(byte)0xA9,
            (byte)0x44,(byte)0x58,(byte)0x65,(byte)0x48,(byte)0x06,(byte)0x78,(byte)0x27,(byte)0x68,
            (byte)0xC0,(byte)0x18,(byte)0xE1,(byte)0x08,(byte)0x82,(byte)0x38,(byte)0xA3,(byte)0x28,
            (byte)0x7D,(byte)0xCB,(byte)0x5C,(byte)0xDB,(byte)0x3F,(byte)0xEB,(byte)0x1E,(byte)0xFB,
            (byte)0xF9,(byte)0x8B,(byte)0xD8,(byte)0x9B,(byte)0xBB,(byte)0xAB,(byte)0x9A,(byte)0xBB,
            (byte)0x75,(byte)0x4A,(byte)0x54,(byte)0x5A,(byte)0x37,(byte)0x6A,(byte)0x16,(byte)0x7A,
            (byte)0xF1,(byte)0x0A,(byte)0xD0,(byte)0x1A,(byte)0xB3,(byte)0x2A,(byte)0x92,(byte)0x3A,
            (byte)0x2E,(byte)0xFD,(byte)0x0F,(byte)0xED,(byte)0x6C,(byte)0xDD,(byte)0x4D,(byte)0xCD,
            (byte)0xAA,(byte)0xBD,(byte)0x8B,(byte)0xAD,(byte)0xE8,(byte)0x9D,(byte)0xC9,(byte)0x8D,
            (byte)0x26,(byte)0x7C,(byte)0x07,(byte)0x6C,(byte)0x64,(byte)0x5C,(byte)0x45,(byte)0x4C,
            (byte)0xA2,(byte)0x3C,(byte)0x83,(byte)0x2C,(byte)0xE0,(byte)0x1C,(byte)0xC1,(byte)0x0C,
            (byte)0x1F,(byte)0xEF,(byte)0x3E,(byte)0xFF,(byte)0x5D,(byte)0xCF,(byte)0x7C,(byte)0xDF,
            (byte)0x9B,(byte)0xAF,(byte)0xBA,(byte)0xBF,(byte)0xD9,(byte)0x8F,(byte)0xF8,(byte)0x9F,
            (byte)0x17,(byte)0x6E,(byte)0x36,(byte)0x7E,(byte)0x55,(byte)0x4E,(byte)0x74,(byte)0x5E,
            (byte)0x93,(byte)0x2E,(byte)0xB2,(byte)0x3E,(byte)0xD1,(byte)0x0E,(byte)0xF0,(byte)0x1E};

        info = new byte[23];

        info[2] = 0x13;
        info[3] = 0x11;
    	// DHCP mode: 0
        info[4] = 0x00;

        System.arraycopy(conf.IP, 0, info, 5, 4);
        System.arraycopy(conf.mask, 0, info, 9, 4);
        System.arraycopy(conf.gateway, 0, info, 13, 4);
        System.arraycopy(conf.dns, 0, info, 17, 4);

        int index;
        for (int i = 0; i < 0x15; ++i) {
            index = xor(info[21], info[i]);
            info[21] = (byte)xor(info[22], table[index*2 + 1]);
            info[22] = table[index*2];
        }
        info = encode(info);
    }

    /**
     * Used to choose a device in a machine.
     */
    public static String getDeviceName() throws IOException {
        List<PcapIf> allDevs = new ArrayList<PcapIf>();
        StringBuilder errBuf = new StringBuilder();

        int r = Pcap.findAllDevs(allDevs, errBuf);
        if (r == Pcap.NOT_OK || allDevs.isEmpty()) {
            System.err.printf("Can't access devices (permission denied?): %s\n",
			      errBuf.toString());
            return null;
        }

        for (int i = 0; i < allDevs.size(); ++i) {
            byte[] mac = allDevs.get(i).getHardwareAddress();
            if (mac == null) {
                continue;
            }
            System.out.printf("%d. %s   :\t%s\n", i, allDevs.get(i).getName(), asString(mac));
        }
        System.out.print(">>> ");
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        int choice = Integer.parseInt(in.readLine());
        return allDevs.get(choice).getName();
    }

    /**
     * Convert a MAC address to readable string
     */
    private static String asString(final byte[] mac) {
        final StringBuilder buf = new StringBuilder();
        for (byte b : mac) {
            if (buf.length() != 0) {
                buf.append(':');
            }
            if (b >= 0 && b < 16) {
                buf.append('0');
            }
            buf.append(Integer.toHexString((b < 0) ? b + 256 : b).toUpperCase());
        }
        return buf.toString();
    }

}
