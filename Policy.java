// package lab5;

import java.util.ArrayList;
import java.util.regex.Pattern;

import java.io.*;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

public class Policy{

    public String file;
    public String name;
    public boolean stateful;
    public String host;
    public String proto;
    public String host_port;
    public String attacker_port;
    public String attacker;
    public ArrayList<String> from_host = new ArrayList<String>();
    public ArrayList<String> to_host = new ArrayList<String>();
    public boolean[] flags = new boolean[6];

    public Policy(String filename){
        this.file = filename;
        BufferedReader br = null;
        try{
            String currentLine;
            br = new BufferedReader(new FileReader(filename));
            while((currentLine = br.readLine()) != null){
                // System.out.println(currentLine);
                if(currentLine.startsWith("host="))
                    this.host = currentLine.substring(5);
                else if(currentLine.startsWith("name="))
                    this.name = currentLine.substring(5);
                else if(currentLine.startsWith("type="))
                    this.stateful = currentLine.contains("stateful");
                else if(currentLine.startsWith("proto="))
                    this.host = currentLine.substring(6);
                else if(currentLine.startsWith("host_port="))
                    this.host_port = currentLine.substring(10);
                else if(currentLine.startsWith("attacker_port="))
                    this.host = currentLine.substring(14);
                else if(currentLine.startsWith("from_host="))
                    this.from_host.add(currentLine.substring(10));
                else if(currentLine.startsWith("to_host="))
                    this.to_host.add(currentLine.substring(8));
                else if(currentLine.startsWith("flags=")){
                    String flagsData = currentLine.substring(6);
                    this.flags[0] = flagsData.contains("S");
                    this.flags[1] = flagsData.contains("A");
                    this.flags[2] = flagsData.contains("F");
                    this.flags[3] = flagsData.contains("R");
                    this.flags[4] = flagsData.contains("P");
                    this.flags[5] = flagsData.contains("U");
                }
            }
        }catch(IOException e){
            e.printStackTrace();
        }finally {
            try {
                if (br != null)
                    br.close();
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
    }

    public boolean evaluate(PcapPacket packet){
        //Do stuff


        return false;
    }

    @Override
    public String toString(){
        String output = "";
        output += String.format("Printing policy file: %s%n", this.file);
        output += String.format("\tname: %s%n", this.name);
        output += String.format("\tstateful: %s%n", (this.stateful ? "true":"false"));
        output += String.format("\thost: %s%n", this.host);
        output += String.format("\tproto: %s%n", this.proto);
        output += String.format("\thost_port: %s%n", this.host_port);
        output += String.format("\tattacker_port: %s%n", this.attacker_port);
        output += String.format("\tattacker: %s%n", this.attacker);
        output += "\tflags:";
        if(flags[0])
            output += " S";
        if(flags[1])
            output += " A";
        if(flags[2])
            output += " F";
        if(flags[3])
            output += " R";
        if(flags[4])
            output += " P";
        if(flags[5])
            output += " U";
        output += String.format("%n");
        for(int i = 0; i < from_host.size(); i++){
            output += String.format("\tfrom_host: %s%n", from_host.get(i));
        }
        for(int i = 0; i < to_host.size(); i++){
            output += String.format("\tto_host: %s%n", to_host.get(i));
        }
        output += String.format("%n");
        return output;
    }
}