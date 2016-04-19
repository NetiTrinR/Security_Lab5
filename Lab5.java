// package lab5;

import java.util.ArrayList;
import java.util.regex.Pattern;
import java.util.Date;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;

import org.jnetpcap.*;
import org.jnetpcap.packet.*;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.util.PcapPacketArrayList;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

/**
 *
 * @author David Schwehr <dpschwehr[at]gmail[.com]> github: dssquared
 * @author Michael Manning <michaelmanning[at]gmail[.com]> github: NetiTrinR
 * @brief
 *
 */
public class Lab5{
    /**
     * Main Class
     * @param args policyfile and pcapfile
     */
    public static void main(String[] args){
        String policyfile = args[0];
        String pcapfile = args[1];

        //Define our policy
        Policy p = new Policy(policyfile);

        // Open the Pcap file
        final StringBuilder errbuf = new StringBuilder();
        Pcap pcap = Pcap.openOffline(pcapfile, errbuf);
        if (pcap == null) {
            System.err.println(errbuf);
            return;
        }

        // Define reading each packet individually and run it through the policy
        PcapPacketHandler<String> handler = new PcapPacketHandler<String>() {
            public void nextPacket(PcapPacket packet, String user) {
                // Do stuff here...
                Tcp tcp = new Tcp();
                Udp udp = new Udp();
                if(packet.hasHeader(tcp)){
                    System.out.println("has tcp header");
                }else if(packet.hasHeader(udp)){
                    System.out.println("Has udp header");
                }else{
                    System.out.println("idk what it is");
                }
                // Something like this?
                // if(policy.evaluate(packet)){
                //     System.out.println("Packet passes policy");
                // }else{
                //     System.out.println("Packet fails policy");
                // }
            }
        };

        // Read each packet via the handler
        try {
            pcap.loop(-1, handler, "Not sure what this string is. Seems arbitary. Lets see wehre it coems out.");
        } finally {
            pcap.close();
        }
     }

}