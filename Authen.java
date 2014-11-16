package jmento;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;

/**
 * Class Authen stands for authentication
 * Generally, a successful authentication process can be devided as following:
 * <ol>
 * <li>Supplicant send EAPoL-START</li>
 * <li>Authenticator send EAP-Request/Identity</li>
 * <li>Supplicant send EAP-Response/Indentity</li>
 * <li>Authenticator send EAP-Request/Challenge</li>
 * <li>Supplicant send EAP-Response/Chanllenge</li>
 * <li>Authenticator send EAP-Success</li>
 * <li>Supplicant is now fully authenticated</li>
 * </ol>
 */
public class Authen extends Packet {

    // The Pcap handle for transmission and capturing
    private Pcap ph;
    StringBuilder err;

    // No. of the echo
    private int echoNo;

    PcapHeader pkt_header;
    JBuffer buffer; 

    /**
     * Initialize the authentication:
     * Set the status to be START
     * Create the packet ready to be sent
     * Open up the pcap handler on the specific net card
     * Set filter on the pcap handle for local ruijie EAP packet 
     */
    Authen(String confPath) {
        super(confPath);
	
        echoNo = 0x0000102B;
        pkt_header = new PcapHeader(JMemory.POINTER);
        buffer = new JBuffer(JMemory.POINTER);
        
        // Open the net card in the configuration
        // snaplen is set to be 128, in practice it never exceeds 100
        // promiscuous set to be 0: Capture your own device only
        // timeout: default 8000 ms
        err = new StringBuilder();
        ph = Pcap.openLive(conf.nic, 1024, 0, 8*1000, err);

        PcapBpfProgram program = new PcapBpfProgram();

        String filter = "ether proto 0x888e and ether dst "
            + macToString(this.localMac);
	
        // The filter is set to accept ethernet EAP packet from 
        // the authenticator and to your local machine
        if (ph.compile(program, filter, 0, 0xFFFFFFFF) != Pcap.OK) {
            System.err.println(ph.getErr());
            return;
        }
	
        if (ph.setFilter(program) != Pcap.OK) {
            System.err.println(ph.getErr());
            return;
        }
    }

    public void finalize() {
        sendLogoff();
        ph.close();
        System.out.println("Quiting");
    }

    public void authenticate() {
        if (sendStart() != 0)
            return;
        int r = ph.nextEx(pkt_header, buffer);
	
        if (r == 0) {
            System.err.println("Timeout in searching for server.");
            System.err.println("Check your cable or your configuration.");
            return;
        } else if (r == -1) {
            System.err.println("Error in capturing Request/Identity packet.");
            return;
        } else if (r != 1) {
            System.err.println("Unknown error.");
            return;
        }

        // MAC address of the nearest server is sent
        destMac = buffer.getByteArray(6, 6);
        byte ID = buffer.getByte(0x13);
        if (sendIdentity(ID) != 0)
            return;

        r = ph.nextEx(pkt_header, buffer);
        if (r == 0) {
            System.err.println("Timeout waiting server for Request/Challenge packet.");
            return;
        } else if (r == -1) {
            System.err.println("Error in capturing Request/Challenge Packet.");
            return;
        } else if (r != 1) {
            System.err.println("Unknown error.");
            return;
        }

        ID = buffer.getByte(0x13);
        byte[] salt = buffer.getByteArray(0x18, buffer.getByte(0x17));
        if (sendChallenge(ID, salt) != 0)
            return;

        r = ph.nextEx(pkt_header, buffer);
        if (r == 0) {
            System.err.println("Timeout in awaiting server for authentication result.");
            return;
        } else if (r == -1) {
            System.err.println("Error in capturing answering packet.");
            return;
        } else if (r != 1) {
            System.err.println("Unknown error.");
            return;
        }
        
        if (buffer.getByte(0x12) != 0x03) {
            System.err.println("Failed in authentication.");
            if (buffer.getByte(0x12) == 0x04) {
                dispInfo();
            }
            return;
        }

        dispInfo();

        // Sending echo packet to maitain online status
        // The offset according to mentohust
        int offset = 0x9D + buffer.getByte(0x1B);
        // The echokey is a 4-bytes encoded integer
        byte[] echoKeyByte = buffer.getByteArray(offset, 4);
        echoKeyByte = encode(echoKeyByte);
        ByteBuffer echoKeyParse = ByteBuffer.wrap(echoKeyByte);
        int echoKey = echoKeyParse.getInt(0);

        do {
            echoKeyByte = int4byte(echoKey + echoNo);
            echoKeyByte = encode(echoKeyByte);
            
            byte[] echoNoByte = int4byte(echoNo);
            echoNoByte = encode(echoNoByte);
            if (sendEcho(echoKeyByte, echoNoByte) != 0) {
                System.err.println("Error in sending echo packet.");
                return;
            }
            this.echoNo++;

            if (hearOffline() == 0) {
                break;
            }
                    
        } while (true);
    }

    // In succuss reponses, the packet contains some news and accout infos
    // In failure ones, the packet contains the reason
    private void dispInfo() {
        int msgLen = buffer.getByte(0x1b);
        msgLen = (msgLen < 0) ? msgLen + 256 : msgLen;
        byte[] msgByte = buffer.getByteArray(0x1c, msgLen);
        try {
            String msg = new String(msgByte, "GBK");
            System.out.println(msg);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        // Your accout infos
        int msgoffset = msgLen + 0xAC;
        if (msgoffset >= buffer.size())
            return;
        msgLen = buffer.size() - msgoffset - 29;
        msgByte = buffer.getByteArray(msgoffset, msgLen);
        try {
            String msg = new String(msgByte, "GBK");
            System.out.println(msg);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }

    private int hearOffline() {
        // Renew the ph for capturing possible failure
        ph.close();
        ph = Pcap.openLive(conf.nic, 1024, 0, conf.echoInterval*1000, err);

        PcapBpfProgram program = new PcapBpfProgram();
        String filter = "ether proto 0x888e and ether dst " +
            macToString(this.localMac) + " and ether src " +
            macToString(this.destMac);

        if (ph.compile(program, filter, 0, 0xFFFFFFFF) != Pcap.OK) {
            System.err.println(ph.getErr());
            return -1;
        }

        if (ph.setFilter(program) != Pcap.OK) {
            System.err.println(ph.getErr());
            return -1;
        }

        int r = ph.nextEx(pkt_header, buffer);
        if (r == 0) {
            // Timeout, meaning we are good
            return -1;
        } else if (r == -1) {
            System.err.println("Error in capturing for possible failure.");
            return -1;
        } else if (r == 1) {
            if (buffer.getByte(0x12) == 0x04) {
                System.out.println("You are now offline.");
                dispInfo();
                return 0;
            }
        } else {
            System.err.println("Unknown error.");
            return -1;
        }
        return -1;
    }

    private int sendStart() {
        buildStart();
        if (ph.sendPacket(this.frame) != 0) {
            System.err.println("Error in sending start packet.");
            return -1;
        }
        return 0;
    }

    private int sendIdentity(byte ID) {
        buildIdentity(ID);
        if (ph.sendPacket(this.frame) != 0) {
            System.err.println("Error in sending identity packet.");
            return -1;
        }
        return 0;
    }

    private int sendChallenge(byte ID, byte[] salt) {
        buildChallenge(ID, salt);
        if (ph.sendPacket(this.frame) != 0) {
            System.err.println("Error in sending challenge packet.");
            return -1;
        }
        return 0;
    }

    private int sendEcho(byte[] echoKeyByte, byte[] echoNoByte) {
        buildEcho(echoKeyByte, echoNoByte);
        if (ph.sendPacket(this.frame) != 0){
            System.err.println("Error in sending echo packet.");
            return -1;
        }
        return 0;
    }

    private int sendLogoff() {
        buildLogoff();
        if (ph.sendPacket(this.frame) != 0) {
            System.err.println("Error in sending logoff packet.");
            return -1;
        }
        return 0;
    }

    // Convert a int to four bytes
    private static byte[] int4byte(int i) {
        byte[] result = new byte[4];
        result[3] = (byte)i;
        result[2] = (byte)(i >>> 8);
        result[1] = (byte)(i >>> 16);
        result[0] = (byte)(i >>> 24);
        return result;
    }

    private static String macToString(byte[] MAC) {
        StringBuilder sb = new StringBuilder(18);
        for (byte b : MAC) {
            if (sb.length() > 0)
            sb.append(':');
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
