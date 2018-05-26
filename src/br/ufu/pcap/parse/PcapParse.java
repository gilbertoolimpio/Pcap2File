package br.ufu.pcap.parse;

import br.ufu.csv.CsvFile;
import br.ufu.pcap.model.PcapItem;
import lombok.Getter;
import lombok.Setter;
import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.IcmpV4CommonPacket.IcmpV4CommonHeader;
import org.pcap4j.packet.IpV4Packet.IpV4Header;
import org.pcap4j.packet.TcpPacket.TcpHeader;
import org.pcap4j.packet.UdpPacket.UdpHeader;

import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class PcapParse {

    @Getter @Setter
    private int countPackage = 0;

    public static List<String> pcapToString(PcapItem pcapItem) {

        List<String> line = new ArrayList<>();
        String sourceIp;
        String sourcePort;
        String destinationIp;
        String destinationPort;

        sourceIp = (pcapItem.getSourceAddress() != null) ? pcapItem.getSourceAddress().replace("/", "") : "";
        sourcePort = (pcapItem.getSourcePort() != null) ? pcapItem.getSourcePort() : "";
        destinationIp = (pcapItem.getDestinationAddress() != null) ? pcapItem.getDestinationAddress().replace("/", "") : "";
        destinationPort = (pcapItem.getDestinationPort() != null) ? pcapItem.getDestinationPort() : "";


        line.add((String.valueOf(pcapItem.getIdPackage()) != null) ? String.valueOf(pcapItem.getIdPackage()) : "");
        line.add(sourceIp + "-" + sourcePort + "-" + destinationIp + "-" + destinationPort); //flow identification
        line.add(sourceIp);
        line.add(sourcePort);
        line.add(destinationIp);
        line.add(destinationPort);
        line.add((pcapItem.getProtocol() != null) ? pcapItem.getProtocol() : "");
        line.add((String.valueOf(pcapItem.getPackageTotalLenght()) != null) ? String.valueOf(pcapItem.getPackageTotalLenght()) : "");
        line.add((String.valueOf(pcapItem.getHeaderLenght()) != null) ? String.valueOf(pcapItem.getHeaderLenght()) : "");
        line.add((pcapItem.getPackageTimestamp() != null) ? pcapItem.getPackageTimestamp() : "");
        line.add((pcapItem.getUrgFlag() != null) ? pcapItem.getUrgFlag() : "");
        line.add((pcapItem.getAckFlag() != null) ? pcapItem.getAckFlag() : "");
        line.add((pcapItem.getPshFlag() != null) ? pcapItem.getPshFlag() : "");
        line.add((pcapItem.getRstFlag() != null) ? pcapItem.getRstFlag() : "");
        line.add((pcapItem.getSynFlag() != null) ? pcapItem.getSynFlag() : "");
        line.add((pcapItem.getFinFlag() != null) ? pcapItem.getFinFlag() : "");
        line.add(String.valueOf(pcapItem.getFlowNumber())); //Flow number
        line.add(pcapItem.getLabel()); //label

        return line;
    }

    public void readPcapFile(String pcapFile) throws PcapNativeException, NotOpenException, IOException {
        PcapHandle handle;
        PcapItem pcapItem = null;
        String csvFile = pcapFile.replace(".pcap",".csv");
        String sourceIp;
        String sourcePort;
        String destinationIp;
        String destinationPort;

        List<String> header = new ArrayList<>();

        try {
            handle = Pcaps.openOffline(pcapFile, PcapHandle.TimestampPrecision.NANO);

        } catch (PcapNativeException e) {
            handle = Pcaps.openOffline(pcapFile);
        }

        FileWriter fileWriter = new FileWriter(csvFile);
        header.add("idPackage");
        header.add("flowIdentification");
        header.add("sourceAddress");
        header.add("sourcePort");
        header.add("destinationAddress");
        header.add("destinationPort");
        header.add("protocol");
        header.add("packageTotalLenght");
        header.add("headerLenght");
        header.add("packageTimestamp");
        header.add("tos");
        header.add("urgFlag");
        header.add("ackFlag");
        header.add("pshFlag");
        header.add("rstFlag");
        header.add("synFlag");
        header.add("finFlag");
        header.add("flowNumber");
        header.add("label");

        CsvFile.writeLine(fileWriter, header);
        while (true) {
            PcapPacket packet = handle.getNextPacket();

            if (packet == null) {
                break;
            }
            EthernetPacket.EthernetHeader ethernetHeader = packet.get(EthernetPacket.class).getHeader();

            //0x0800 = Ipv4 Header
            if (ethernetHeader.getType().valueAsString().equals("0x0800")) {
                IpV4Header ipV4Header = (IpV4Header) packet.getPacket().getPayload().getHeader();

                //Cria o objeto Pcap
                pcapItem = new PcapItem();
                pcapItem.setIdPackage(countPackage);
                pcapItem.setPackageTimestamp(packet.getTimestamp().toString());
                pcapItem.setTos(ipV4Header.getTos().toString());
                pcapItem.setPackageTotalLenght(packet.getPacket().length());
                pcapItem.setSourceAddress(ipV4Header.getSrcAddr().toString());
                pcapItem.setDestinationAddress(ipV4Header.getDstAddr().toString());



                //TCP Protocol
                if (ipV4Header.getProtocol().valueAsString().equals("6")) {
                    TcpHeader tcpHeader = (TcpHeader) packet.getPacket().getPayload().getPayload().getHeader();
                    pcapItem.setProtocol("tcp_ip");
                    pcapItem.setSourcePort(tcpHeader.getSrcPort().valueAsString());
                    pcapItem.setDestinationPort(tcpHeader.getDstPort().valueAsString());
                    pcapItem.setHeaderLenght(tcpHeader.length());
                    pcapItem.setAckFlag(String.valueOf(tcpHeader.getAck()));
                    pcapItem.setFinFlag(String.valueOf(tcpHeader.getFin()));
                    pcapItem.setPshFlag(String.valueOf(tcpHeader.getPsh()));
                    pcapItem.setRstFlag(String.valueOf(tcpHeader.getRst()));
                    pcapItem.setSynFlag(String.valueOf(tcpHeader.getSyn()));
                    pcapItem.setUrgFlag(String.valueOf(tcpHeader.getUrg()));
                }

                //UDP Protocol
                if (ipV4Header.getProtocol().valueAsString().equals("17")) {

                    UdpHeader udpHeader = (UdpHeader) packet.getPacket().getPayload().getPayload().getHeader();

                    pcapItem.setProtocol("udp_ip");
                    pcapItem.setSourcePort((udpHeader != null) ? udpHeader.getSrcPort().valueAsString() : "");
                    pcapItem.setDestinationPort((udpHeader != null) ? udpHeader.getDstPort().valueAsString() : "");
                    pcapItem.setHeaderLenght((udpHeader != null) ? udpHeader.getLength() : 0);
                    pcapItem.setAckFlag("");
                    pcapItem.setFinFlag("");
                    pcapItem.setPshFlag("");
                    pcapItem.setRstFlag("");
                    pcapItem.setSynFlag("");
                    pcapItem.setUrgFlag("");
                }

                //Captura os pacotes ICMP
                if (ipV4Header.getProtocol().valueAsString().equals("1")) {

                    IcmpV4CommonHeader icmpV4CommonHeader = (IcmpV4CommonHeader) packet.getPacket().getPayload().getPayload().getHeader();
                    pcapItem.setProtocol("icmp_ip");

                    pcapItem.setSourcePort("");
                    pcapItem.setDestinationPort("");
                    pcapItem.setAckFlag("");
                    pcapItem.setFinFlag("");
                    pcapItem.setPshFlag("");
                    pcapItem.setRstFlag("");
                    pcapItem.setSynFlag("");
                    pcapItem.setUrgFlag("");
                }
            } else if (ethernetHeader.getType().valueAsString().equals("0x86dd")) {
                IpV6Packet.IpV6Header ipV6Header = (IpV6Packet.IpV6Header) packet.getPacket().getPayload().getHeader();

                //Cria o objeto Pcap
                pcapItem = new PcapItem();
                pcapItem.setIdPackage(countPackage);
                pcapItem.setPackageTimestamp(packet.getTimestamp().toString());

                pcapItem.setPackageTotalLenght(packet.getPacket().length());
                pcapItem.setSourceAddress(ipV6Header.getSrcAddr().toString());
                pcapItem.setDestinationAddress(ipV6Header.getDstAddr().toString());


                //Captura os pacotes TCP
                if (ipV6Header.getProtocol().valueAsString().equals("6")) {

                    TcpPacket.TcpHeader tcpV6Header = (TcpPacket.TcpHeader) packet.getPacket().getPayload().getPayload().getHeader();
                    pcapItem.setProtocol("tcp_ip_v6");
                    pcapItem.setSourcePort(tcpV6Header.getSrcPort().valueAsString());
                    pcapItem.setDestinationPort(tcpV6Header.getDstPort().valueAsString());
                    pcapItem.setHeaderLenght(tcpV6Header.length());
                    pcapItem.setAckFlag(String.valueOf(tcpV6Header.getAck()));
                    pcapItem.setFinFlag(String.valueOf(tcpV6Header.getFin()));
                    pcapItem.setPshFlag(String.valueOf(tcpV6Header.getPsh()));
                    pcapItem.setRstFlag(String.valueOf(tcpV6Header.getRst()));
                    pcapItem.setSynFlag(String.valueOf(tcpV6Header.getSyn()));
                    pcapItem.setUrgFlag(String.valueOf(tcpV6Header.getUrg()));
                }
                //Captura os pacotes UDP IPV6
                if (ipV6Header.getProtocol().valueAsString().equals("17")) {

                    UdpPacket.UdpHeader udpHeader = (UdpPacket.UdpHeader) packet.getPacket().getPayload().getPayload().getHeader();
                    pcapItem.setProtocol("udp_ip_v6");
                    pcapItem.setSourcePort((udpHeader != null) ? udpHeader.getSrcPort().valueAsString() : "");
                    pcapItem.setDestinationPort((udpHeader != null) ? udpHeader.getDstPort().valueAsString() : "");
                    pcapItem.setHeaderLenght((udpHeader != null) ? udpHeader.getLength() : 0);
                    pcapItem.setAckFlag("");
                    pcapItem.setFinFlag("");
                    pcapItem.setPshFlag("");
                    pcapItem.setRstFlag("");
                    pcapItem.setSynFlag("");
                    pcapItem.setUrgFlag("");
                }

            } else if (ethernetHeader.getType().valueAsString().equals("0x0806")) {
                ArpPacket.ArpHeader arpHeader = (ArpPacket.ArpHeader) packet.getPacket().getPayload().getHeader();
                //Cria o objeto Pcap
                pcapItem = new PcapItem();
                pcapItem.setIdPackage(countPackage);
                pcapItem.setPackageTimestamp(packet.getTimestamp().toString());

                pcapItem.setPackageTotalLenght(packet.getPacket().length());
                pcapItem.setSourceAddress(arpHeader.getSrcProtocolAddr().toString());
                pcapItem.setDestinationAddress(arpHeader.getDstProtocolAddr().toString());

                pcapItem.setProtocol("arp_ip");

                pcapItem.setSourcePort("");
                pcapItem.setDestinationPort("");
                pcapItem.setAckFlag("");
                pcapItem.setFinFlag("");
                pcapItem.setPshFlag("");
                pcapItem.setRstFlag("");
                pcapItem.setSynFlag("");
                pcapItem.setUrgFlag("");
            } else {
                continue;
            }

            List<String> line = new ArrayList<>();

            sourceIp = (pcapItem.getSourceAddress() != null) ? pcapItem.getSourceAddress().replace("/", "") : String.valueOf(0);
            sourcePort = (pcapItem.getSourcePort() != null) ? pcapItem.getSourcePort() : String.valueOf(0);
            destinationIp = (pcapItem.getDestinationAddress() != null) ? pcapItem.getDestinationAddress().replace("/", "") : String.valueOf(0);
            destinationPort = (pcapItem.getDestinationPort() != null) ? pcapItem.getDestinationPort() : String.valueOf(0);
            pcapItem.setFlowIdentification(sourceIp + sourcePort + destinationIp + destinationPort);

            line.add((String.valueOf(pcapItem.getIdPackage()) != null) ? String.valueOf(pcapItem.getIdPackage()) : "");
            line.add(sourceIp + "-" + sourcePort + "-" + destinationIp + "-" + destinationPort); //flow identification
            line.add(sourceIp);
            line.add(sourcePort);
            line.add(destinationIp);
            line.add(destinationPort);
            line.add((pcapItem.getProtocol() != null) ? pcapItem.getProtocol() : "");
            line.add((String.valueOf(pcapItem.getPackageTotalLenght()) != null) ? String.valueOf(pcapItem.getPackageTotalLenght()) : String.valueOf(0));
            line.add((String.valueOf(pcapItem.getHeaderLenght()) != null) ? String.valueOf(pcapItem.getHeaderLenght()) : String.valueOf(0));
            line.add((pcapItem.getPackageTimestamp() != null) ? pcapItem.getPackageTimestamp() : "");
            line.add((pcapItem.getTos() != null)? pcapItem.getTos(): "");
            line.add((pcapItem.getUrgFlag() != null) ? pcapItem.getUrgFlag() : "");
            line.add((pcapItem.getAckFlag() != null) ? pcapItem.getAckFlag() : "");
            line.add((pcapItem.getPshFlag() != null) ? pcapItem.getPshFlag() : "");
            line.add((pcapItem.getRstFlag() != null) ? pcapItem.getRstFlag() : "");
            line.add((pcapItem.getSynFlag() != null) ? pcapItem.getSynFlag() : "");
            line.add((pcapItem.getFinFlag() != null) ? pcapItem.getFinFlag() : "");
            line.add(""); //Flow number
            line.add(""); //label

            CsvFile.writeLine(fileWriter, line);

            System.out.print("Number of package: " + countPackage + "\r");
            countPackage++;

        }

        fileWriter.flush();
        fileWriter.close();
        setCountPackage(countPackage);

    }

}
