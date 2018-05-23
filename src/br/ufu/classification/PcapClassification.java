package br.ufu.classification;

import br.ufu.flow.model.FlowItem;
import br.ufu.pcap.model.PcapItem;
import br.ufu.pcap.parse.PcapParse;
import com.opencsv.CSVReader;
import com.opencsv.CSVWriter;
import lombok.Getter;
import lombok.Setter;

import java.io.FileWriter;
import java.io.IOException;
import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

@SuppressWarnings("deprecation")
public class PcapClassification {

    @Getter
    @Setter
    private String pcapFile;
    @Getter
    @Setter
    private String flowFile;

    public PcapClassification(String flowFile, String pcapFile) {
        this.flowFile = flowFile;
        this.pcapFile = pcapFile;
    }

    private FlowItem createFlowItem(String[] flowItem) {
        FlowItem flow = new FlowItem();

        flow.setSrcAddress(flowItem[1]);
        flow.setSrcPort(flowItem[2]);
        flow.setNumberSrcPackages(((flowItem[8]).equals("")) ? 0 : Integer.parseInt(flowItem[8]));
        flow.setDstAddress(flowItem[3]);
        flow.setDstPort(flowItem[4]);
        flow.setNumberDstPackages(((flowItem[9]).equals("")) ? 0 : Integer.parseInt(flowItem[9]));
        flow.setKeyFlow(flowItem[85]);
        flow.setFlowUniqueId(((flowItem[86]).equals("")) ? 0 : Integer.parseInt(flowItem[86]));
        flow.setLabel(flowItem[84]);
        flow.setTotalPackages(flow.getNumberDstPackages() + flow.getNumberSrcPackages());
        return flow;
    }

    private PcapItem createPcapItem(String[] pcapItem) {
        PcapItem pcap = new PcapItem();

        pcap.setIdPackage(((pcapItem[0]).equals("")) ? 0 : Integer.parseInt(pcapItem[0]));
        pcap.setFlowIdentification(pcapItem[1]);
        pcap.setSourceAddress(pcapItem[2]);
        pcap.setSourcePort(pcapItem[3]);
        pcap.setDestinationAddress(pcapItem[4]);
        pcap.setDestinationPort(pcapItem[5]);
        pcap.setProtocol(pcapItem[6]);
        pcap.setPackageTotalLenght(((pcapItem[7]).equals("")) ? 0 : Integer.parseInt(pcapItem[7]));
        pcap.setHeaderLenght(((pcapItem[8]).equals("")) ? 0 : Integer.parseInt(pcapItem[8]));
        pcap.setPackageTimestamp(pcapItem[9]);
        pcap.setUrgFlag(pcapItem[10]);
        pcap.setAckFlag(pcapItem[11]);
        pcap.setPshFlag(pcapItem[12]);
        pcap.setRstFlag(pcapItem[13]);
        pcap.setSynFlag(pcapItem[14]);
        pcap.setFinFlag(pcapItem[15]);
        pcap.setFlowNumber(((pcapItem[16]).equals("")) ? 0 : Integer.parseInt(pcapItem[16]));
        pcap.setLabel(pcapItem[17]);

        return pcap;
    }

    private String inversePcap(PcapItem pcapItem) {

        return pcapItem.getDestinationAddress() + "-" + pcapItem.getDestinationPort() + "-" + pcapItem.getSourceAddress() + "-" + pcapItem.getSourcePort();
    }

    public void classification() {
        PcapItem pcapItem;
        FlowItem flowItem;
        String[] flowLine;
        String[] pcapLine;
        HashMap<String, LinkedList<FlowItem>> flowClassified = new HashMap<>();
        Iterator flowRead;
        List<String> line;
        boolean firstLine = true;
        boolean flowFirstLine = true;
        boolean firstAll = true;
        int packages;
        int packageCount;
        int totalPackage;
        LinkedList<FlowItem> keyFlow;

        try {
            Reader flowReader = Files.newBufferedReader(Paths.get(flowFile));
            Reader pcapReader = Files.newBufferedReader(Paths.get(pcapFile));

            CSVReader flow = new CSVReader(flowReader);
            CSVReader pcap = new CSVReader(pcapReader, ';');

            CSVWriter writer = new CSVWriter(new FileWriter(".\\file\\Pcap_Classification.csv"));

            System.out.println("Vou ler tudo!");
            flowRead = flow.readAll().iterator();
            while (flowRead.hasNext()) {

                if (flowFirstLine) {
                    flowFirstLine = false;
                    flowRead.next();
                    continue;
                }

                flowItem = createFlowItem((String[]) flowRead.next());

                if (flowClassified.containsKey(flowItem.getKeyFlow())) {
                    keyFlow = flowClassified.get(flowItem.getKeyFlow());
                } else {
                    keyFlow = new LinkedList<>();
                }
                keyFlow.addLast(flowItem);
                flowClassified.put(flowItem.getKeyFlow(), keyFlow);
            }
            flow.close();

            System.out.println("Li Tudo");
            packageCount = 0;

            System.out.println("Começando a ler os pcaps - Vamos Lá");
            firstLine = true;
            while ((pcapLine = pcap.readNext()) != null) {
                if (firstLine) {
                    if (firstAll) {
                        writer.writeNext(pcapLine);
                        writer.flush();
                        firstLine = false;
                        firstAll = false;
                        continue;
                    }
                    firstLine = false;
                    continue;
                }

                pcapItem = createPcapItem(pcapLine);

                if (flowClassified.containsKey(pcapItem.getFlowIdentification())) {

                    if (flowClassified.get(pcapItem.getFlowIdentification()).getFirst().getTotalPackages() > 0) {
                        FlowItem item = flowClassified.get(pcapItem.getFlowIdentification()).getFirst();
                        item.updateTotalPackages();

                        pcapItem.setLabel(item.getLabel());
                        pcapItem.setFlowNumber(item.getFlowUniqueId());

                        line = PcapParse.pcapToString(pcapItem);
                        System.out.println("classifiquei line: " + line);
                        writer.writeNext(line.toArray(new String[line.size()]));
                        writer.flush();

                        if (item.getTotalPackages() == 0) {
                            flowClassified.remove(pcapItem.getFlowIdentification());
                        }
                    }
                    packageCount++;
                } else if (flowClassified.containsKey(inversePcap(pcapItem))) {

                    FlowItem item = flowClassified.get(inversePcap(pcapItem)).getFirst();
                    item.updateTotalPackages();

                    pcapItem.setLabel(item.getLabel());
                    pcapItem.setFlowNumber(item.getFlowUniqueId());

                    line = PcapParse.pcapToString(pcapItem);
                    System.out.println("classifiquei line: " + line);
                    writer.writeNext(line.toArray(new String[line.size()]));
                    writer.flush();

                    if (item.getTotalPackages() == 0) {
                        flowClassified.remove(inversePcap(pcapItem));
                    }
                    packageCount++;
                }

            }
            pcap.close();
            pcapReader.close();

            flowReader.close();
            writer.close();
            System.out.println("Total de Pacotes classificados: " + packageCount);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
