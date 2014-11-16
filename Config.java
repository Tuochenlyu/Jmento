package jmento;

import java.io.BufferedReader;
import java.io.Console;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Properties;

/** 
 * The Configuration class including a Property hash
 * Keys:
 * <ul>
 * <li>Username</li>
 * <li>Password   (Encoded)</li>
 * <li>Nic</li>
 * <li>IP</li>
 * <li>Mask</li>
 * <li>Gateway</li>
 * <li>DNS</li>
 * <li>Version</li>
 * </ul>
 */
public class Config {

    private static final String[] keys = new String[] {
	"Username",
	"Password",
	"Nic",
	"IP",
	"Mask",
	"Gateway",
	"DNS",
	"PingHost",
	"Version",
	"EchoInterval"
    };

    private Properties prop;

    // All the configurations
    public byte[] username;
    public byte[] password;
    public String nic;
    public byte[] IP;
    public byte[] mask;
    public byte[] gateway;
    public byte[] dns;
    public byte[] pingHost;
    public byte[] version;
    public int echoInterval;
    public int DHCPmode;

    /**
     * Load the configuration from confPath
     */
    Config(String confPath) {
        prop = new Properties();
        try {
            prop.load(new FileInputStream(confPath));
        } catch (IOException ex) {
            ex.printStackTrace();
            return;
        }

        if (!check()) {
            System.out.println("Configuration incomplete, please reconfirm or specify certain items.");
            System.out.println("If confirmed, just press enter.");
            try {
                init();
            } catch (IOException e) {
                e.printStackTrace();
                return;
            }

            // Save the configuration if modified.
            String comments = "Configurations for Ruijie authentication";
            try {
                prop.store((new FileOutputStream(confPath)), comments);
            } catch (IOException ex) {
                ex.printStackTrace();
                return;
            }
        }

        username = prop.getProperty("Username").getBytes();
        password = prop.getProperty("Password").getBytes();
        nic = prop.getProperty("Nic");
        echoInterval = Integer.parseInt(prop.getProperty("EchoInterval"));

        // Version has two bytes, we have to convert the float-like string to this format
        version = new byte[2];

        String[] parts = prop.getProperty("Version").split("\\.");
        version[0] = (byte)(Integer.parseInt(parts[0]));
        version[1] = (byte)(Integer.parseInt(parts[1]));
        
        try {
            IP = InetAddress.getByName(prop.getProperty("IP")).getAddress();
            mask = InetAddress.getByName(prop.getProperty("Mask")).getAddress();
            gateway = InetAddress.getByName(prop.getProperty("Gateway")).getAddress();
            dns = InetAddress.getByName(prop.getProperty("DNS")).getAddress();
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
    }
    
    /**
     * When the configuration isn't complete,
     * initialize it manually.
     */
    private void init() throws IOException {
	BufferedReader in = 
	    new BufferedReader(new InputStreamReader(System.in));
        for (String s : keys) {
            if (s == "Password") {
                if (prop.getProperty(s) == null || 
                    prop.getProperty(s).length() == 0) {
                    Console console = System.console();
                    console.printf("Password:");
                    char[] password = console.readPassword();
                    prop.setProperty("Password", (new String(password)));
                    continue;
                }
                else continue;
            }

            if (s == "Nic") {
                System.out.println("Choose your network device");
                prop.setProperty(s, Packet.getDeviceName());
                continue;
            }

            System.out.print(s);
            if (prop.getProperty(s) == null || 
                prop.getProperty(s).length() == 0) {
                System.out.print(":");
                String value = in.readLine();
                prop.setProperty(s, value);
            }
            else {
                System.out.print("(" + prop.getProperty(s) + "):");
                String value = in.readLine();
                if (value.length() != 0)
                    prop.setProperty(s, value);
            }
        }
    }

    // In java.util.properties, when the property is not specified,
    // the function getProperty doesn't return null
    private Boolean check() {
        for (String s : keys) {
            if (prop.getProperty(s) == null ||
                prop.getProperty(s).length() == 0)
                return false;
        }
        return true;
    }
}
