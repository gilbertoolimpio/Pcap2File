import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.util.ByteArrays;

import java.io.EOFException;
import java.util.concurrent.TimeoutException;

@SuppressWarnings("javadoc")
public class GetRawNextPacketEx {

    private static final int COUNT = 100;

    private static final String PCAP_FILE_KEY = GetRawNextPacketEx.class.getName() + ".pcapFile";
    private static final String PCAP_FILE = System.getProperty(PCAP_FILE_KEY, ".\\file\\analise.pcap");
    private static final String COUNT_KEY = GetRawNextPacketEx.class.getName() + ".count";
    //private static final int COUNT = Integer.getInteger(COUNT_KEY, 10);

    private static final String READ_TIMEOUT_KEY = GetRawNextPacketEx.class.getName() + ".readTimeout";
    private static final int READ_TIMEOUT = Integer.getInteger(READ_TIMEOUT_KEY, 10); // [ms]

    private static final String SNAPLEN_KEY = GetRawNextPacketEx.class.getName() + ".snaplen";
    private static final int SNAPLEN = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]

    private GetRawNextPacketEx() {
    }

    public static void main(String[] args) throws PcapNativeException, NotOpenException {
/*
        String filter = args.length != 0 ? args[0] : "";

        System.out.println(COUNT_KEY + ": " + COUNT);
        System.out.println(READ_TIMEOUT_KEY + ": " + READ_TIMEOUT);
        System.out.println(SNAPLEN_KEY + ": " + SNAPLEN);
        System.out.println("\n");

        PcapNetworkInterface nif;
        try {
            nif = new NifSelector().selectNetworkInterface();
        } catch (IOException e) {
            e.printStackTrace();
            return;
        }

        if (nif == null) {
            return;
        }

        System.out.println(nif.getName() + "(" + nif.getDescription() + ")");

        PcapHandle handle = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);

        handle.setFilter(filter, BpfCompileMode.OPTIMIZE);
*/

        PcapHandle handle;
        try {
            handle = Pcaps.openOffline(PCAP_FILE, PcapHandle.TimestampPrecision.NANO);
        } catch (PcapNativeException e) {
            handle = Pcaps.openOffline(PCAP_FILE);
        }
        int num = 0;
        while (true) {
            try {
                PcapPacket packet = handle.getNextPacketEx();

                EthernetPacket.EthernetHeader eHeader = (EthernetPacket.EthernetHeader) packet.getPacket().getHeader();

                /**
                 * Consultar os Ethertype em https://en.wikipedia.org/wiki/EtherType
                 * 0x0800 = IPV4
                 * 0x0806 = ARP
                 * 0x8100 = VLAN
                 * 0x86DD - IPV6
                 *
                 * Número utilizado dos protocolos poderá ser consultado em:
                 * https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
                 */

                //Captura os pacotes de IPV4
                if (eHeader.getType().valueAsString().equals("0x0800")) {
                    IpV4Packet.IpV4Header ipV4Header = (IpV4Packet.IpV4Header) packet.getPacket().getPayload().getHeader();

                    //Captura os pacotes TCP
                    if (ipV4Header.getProtocol().valueAsString().equals("6")) {

                        TcpPacket.TcpHeader headerTcp = (TcpPacket.TcpHeader) packet.getPacket().getPayload().getPayload().getHeader();

                        System.out.println("=========== TCP Header ================");
                        System.out.println("Source Port (16 bits): " + headerTcp.getSrcPort());
                        System.out.println("Destination Port (16 bits): " + headerTcp.getDstPort());
                        System.out.println("Sequence Number (32 bits): " + headerTcp.getSequenceNumberAsLong());
                        System.out.println("Acknowledge Number (32 bits): " + headerTcp.getAcknowledgmentNumberAsLong());
                        System.out.println("DataOffset (4 bits): " + headerTcp.getDataOffset());
                        System.out.println("Reserved (3 bits):" + headerTcp.getReserved());
                        System.out.println("Urg (1 bit): " + headerTcp.getUrg());
                        System.out.println("Ack (1 bit): " + headerTcp.getAck());
                        System.out.println("Psh (1 bit): " + headerTcp.getPsh());
                        System.out.println("Rst (1 bit): " + headerTcp.getRst());
                        System.out.println("Syn (1 bit): " + headerTcp.getSyn());
                        System.out.println("Fin (1 bit): " + headerTcp.getFin());
                        System.out.println("Window Size (16 bits): " + ByteArrays.toHexString(headerTcp.getWindow(), " "));
                        System.out.println("CheckSum (16 bits): " + ByteArrays.toHexString(headerTcp.getChecksum(), " "));
                        for (int i = 0; i < headerTcp.getOptions().size(); i++) {
                            System.out.println("DataOffset " + i + ": " + headerTcp.getOptions().get(i));
                        }
                        System.out.println("Padding: " + headerTcp.getPadding());
                        System.out.println();
                    }

                    //Captura os pacotes UDP
                    if (ipV4Header.getProtocol().valueAsString().equals("17")) {

                        UdpPacket.UdpHeader headerUdp = (UdpPacket.UdpHeader) packet.getPacket().getPayload().getPayload().getHeader();

                        System.out.println("=========== UDP Header ================");
                        System.out.println("Source Port (16 bits): " + headerUdp.getSrcPort());
                        System.out.println("Destination Port (16 bits): " + headerUdp.getDstPort());
                        System.out.println("Length (16 bits): " + headerUdp.getLengthAsInt());
                        System.out.println("Checksum (16 bits): " + headerUdp.getChecksum());
                    }
                }

                //Captura os pacotes ARP
                if (eHeader.getType().valueAsString().equals("0x0806")) {
                    ArpPacket.ArpHeader arpHeader = (ArpPacket.ArpHeader) packet.getPacket().getPayload().getHeader();


                }

                if (eHeader.getType().valueAsString().equals("0x8100")) {

                }

                if (eHeader.getType().valueAsString().equals("0x86DD")) {

                }


                //System.out.println("Ethernet Package: " + pct);

                num++;
                if (num >= COUNT) {
                    break;
                }
            } catch (TimeoutException e) {
            } catch (EOFException e) {
                e.printStackTrace();
            }
        }

        handle.close();
    }

}