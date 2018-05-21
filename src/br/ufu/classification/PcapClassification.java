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

    private String inverseFlow(FlowItem flowItem) {

        return flowItem.getDstAddress() + "-" + flowItem.getDstPort() + "-" + flowItem.getSrcAddress() + "-" + flowItem.getSrcPort();
    }

    private void classificationPackages() {


    }

    public void openFiles() {
        PcapItem pcapItem;
        FlowItem flowItem;
        String[] flowLine;
        String[] pcapLine;
        HashMap<Integer, Integer> flowClassified = new HashMap<>();
        List<String> line;
        boolean firstLine = true;
        boolean flowFirstLine = true;
        boolean firstAll = true;

        int packageCount;
        int totalPackage;

        try {
            Reader flowReader = Files.newBufferedReader(Paths.get(flowFile));

            CSVReader flow = new CSVReader(flowReader);
            //CSVReader pcap = new CSVReader(pcapReader, ';');

            CSVWriter writer = new CSVWriter(new FileWriter(".\\file\\Pcap_Classification.csv"));

            while ((flowLine = flow.readNext()) != null) {
                if (flowFirstLine) {
                    flowFirstLine = false;
                    continue;
                }
                flowItem = createFlowItem(flowLine);
                totalPackage = flowItem.getNumberDstPackages() + flowItem.getNumberSrcPackages();
                packageCount = 0;
                System.out.println(flowItem.toString());
                Reader pcapReader = Files.newBufferedReader(Paths.get(pcapFile));
                CSVReader pcap = new CSVReader(pcapReader, ';');
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
                    if (!pcapItem.getLabel().equals("")) {
                        continue;
                    }

                    if ((flowItem.getKeyFlow().equals(pcapItem.getFlowIdentification())
                            || inverseFlow(flowItem).equals(pcapItem.getFlowIdentification()))
                            && pcapItem.getLabel().equals("")
                            && packageCount < totalPackage
                            && !flowClassified.containsKey(pcapItem.getIdPackage())) {

                        pcapItem.setLabel(flowItem.getLabel());
                        pcapItem.setFlowNumber(flowItem.getFlowUniqueId());

                        line = PcapParse.pcapToString(pcapItem);

                        writer.writeNext(line.toArray(new String[line.size()]));
                        writer.flush();

                        flowClassified.put(pcapItem.getIdPackage(), flowItem.getFlowUniqueId());
                        System.out.println("Package Count: " + packageCount);
                        packageCount++;
                    }

                    if (packageCount >= totalPackage) {
                        break;
                    }
                }
                pcap.close();
                pcapReader.close();
            }

            flowReader.close();

            writer.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
