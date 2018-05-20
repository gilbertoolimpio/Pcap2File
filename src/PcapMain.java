import br.ufu.csv.CsvFile;
import br.ufu.pcap.model.PcapItem;
import br.ufu.pcap.parse.PcapParse;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

public class PcapMain{
    public static void main(String args[]) {

/*        int count = 0;
        boolean next = true;
        try {

            while (next){
                String command = "C:\\Program Files\\Wireshark\\tshark.exe -r .\\file\\testbed-13jun.pcap tcp.stream eq " + count;


                Process process = Runtime.getRuntime().exec(command);
                ExecuteTshark input = new ExecuteTshark(process.getInputStream());
                System.out.println("Flow number: " + count);
                next = input.execTshark();

                count += 1;
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        System.out.println("Total flow: " + count);*/

        //String pcapFile = ".\\file\\New_wednesday.pcap";
        //String csvFile = ".\\file\\New_wednesday.csv";
        //PcapParse pcapParse = new PcapParse();
        //List<PcapItem> pcapItems = new ArrayList<>();
        //int count = 0;
        CsvFile.insertNewId(".\\file\\Wednesday-workingHours.pcap_ISCX.csv");
     //   try {
            //pcapParse.readPcapFile(pcapFile);

/*            List<String> header = new ArrayList<>();

            FileWriter fileWriter = new FileWriter(csvFile);
            header.add("idPackage");
            header.add("sourceAddress");
            header.add("sourcePort");
            header.add("destinationAddress");
            header.add("destinationPort");
            header.add("protocol");
            header.add("packageTotalLenght");
            header.add("packageTimestamp");
            header.add("urgFlag");
            header.add("ackFlag");
            header.add("pshFlag");
            header.add("rstFlag");
            header.add("synFlag");
            header.add("finFlag");

            CsvFile.writeLine(fileWriter, header);
            System.out.println("Criei o header do csv");
            for (PcapItem pcap : pcapItems) {
                List<String> line = new ArrayList<>();
                //System.out.println("Pacote: " + count + " - " + pcap.toString());

                line.add((String.valueOf(pcap.getIdPackage()) != null) ? String.valueOf(pcap.getIdPackage()) : "");
                line.add((pcap.getSourceAddress() != null) ? pcap.getSourceAddress().replace("/","") : "");
                line.add((pcap.getSourcePort() != null) ? pcap.getSourcePort() : "");
                line.add((pcap.getDestinationAddress() != null) ? pcap.getDestinationAddress().replace("/","") : "");
                line.add((pcap.getDestinationPort() != null) ? pcap.getDestinationPort() : "");
                line.add((pcap.getProtocol() != null) ? pcap.getProtocol() : "");
                line.add((String.valueOf(pcap.getPackageTotalLenght()) != null) ? String.valueOf(pcap.getPackageTotalLenght()) : "");
                line.add((pcap.getPackageTimestamp() != null) ? pcap.getPackageTimestamp() : "");
                line.add((pcap.getUrgFlag() != null) ? pcap.getUrgFlag() : "");
                line.add((pcap.getAckFlag() != null) ? pcap.getAckFlag() : "");
                line.add((pcap.getPshFlag() != null) ? pcap.getPshFlag() : "");
                line.add((pcap.getPshFlag() != null) ? pcap.getPshFlag() : "");
                line.add((pcap.getRstFlag() != null) ? pcap.getRstFlag() : "");
                line.add((pcap.getSynFlag() != null) ? pcap.getSynFlag() : "");
                line.add((pcap.getFinFlag() != null) ? pcap.getFinFlag() : "");


                CsvFile.writeLine(fileWriter, line);
                System.out.println("Escrevi o pacote: " + count);
                count++;
            }

            fileWriter.flush();
            fileWriter.close();

        } catch (PcapNativeException e) {
            e.printStackTrace();
        } catch (NotOpenException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();*/

       // } catch (PcapNativeException e) {
         //   e.printStackTrace();
       // } catch (IOException e) {
         //   e.printStackTrace();
        //} catch (NotOpenException e) {
          //  e.printStackTrace();
        //}

//        FlowXmlParse flowXmlParse = new FlowXmlParse();
//        List<FlowXmlItem> flowXmlItems = flowXmlParse.readXmlFlow("D:\\TestbedSunJun13Flows.xml");
//        String csvFile = ".\\file\\TestbedSunJun13.csv";
//        List<String> header = new ArrayList<>();
//        int flow = 0;
//
//        try {
//            FileWriter fileWriter = new FileWriter(csvFile);
//            header.add("idPackage");
//            header.add("appName");
//            header.add("totalSourceBytes");
//            header.add("totalDestinationBytes");
//            header.add("totalDestinationPackets");
//            header.add("totalSourcePackets");
//            //header.add("sourcePayloadAsBase64");
//            //header.add("sourcePayloadAsUTF");
//            //header.add("destinationPayloadAsBase64");
//            //header.add("destinationPayloadAsUTF");
//            header.add("direction");
//            header.add("sourceTCPFlagsDescription");
//            header.add("destinationTCPFlagsDescription");
//            header.add("source");
//            header.add("protocolName");
//            header.add("sourcePort");
//            header.add("destination");
//            header.add("destinationPort");
//            header.add("startDateTime");
//            header.add("stopDateTime");
//            header.add("Tag");
//
//            CsvFile.writeLine(fileWriter, header );
//
//            for (FlowXmlItem itens : flowXmlItems){
//                List<String> line = new ArrayList<>();
//
//                line.add(String.valueOf(flow));
//                line.add(itens.getAppName());
//                line.add(itens.getTotalSourceBytes());
//                line.add(itens.getTotalDestinationBytes());
//                line.add(itens.getTotalDestinationPackets());
//                line.add(itens.getTotalSourcePackets());
//                //line.add(itens.getSourcePayloadAsBase64());
//                //line.add(itens.getSourcePayloadAsUTF());
//                //line.add(itens.getDestinationPayloadAsBase64());
//                //line.add(itens.getDestinationPayloadAsUTF());
//                line.add(itens.getDirection());
//                line.add(itens.getSourceTCPFlagsDescription());
//                line.add(itens.getDestinationTCPFlagsDescription());
//                line.add(itens.getSource());
//                line.add(itens.getProtocolName());
//                line.add(itens.getSourcePort());
//                line.add(itens.getDestination());
//                line.add(itens.getDestinationPort());
//                line.add(itens.getStartDateTime());
//                line.add(itens.getStopDateTime());
//                line.add(itens.getTag());
//
//                CsvFile.writeLine(fileWriter, line);
//
//                flow += 1;
//            }
//
//            fileWriter.flush();
//            fileWriter.close();
//        } catch (IOException e) {
//            e.printStackTrace();
//        }

    }
}
