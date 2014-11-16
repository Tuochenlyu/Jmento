package jmento;

public class Jmento {
    public static void main (String[] args) {
        // Possible command options:
        // -d   dynamic IP address, using native dhcp client
        // -f   using specific configuration file following
        //      this option

        String confPath;
        for (int i = 0; i < args.length; ++i) {
            if (args[i].equals("-f") && (i != args.length - 1)) {
                confPath = args[i + 1];
                break;
           }
        }



        Config conf = new Config(confPath);

        for (String s : args) {
            if (s.equals("-d")) {
                conf.DHCPmode = 1;
                break;
            }
        }


