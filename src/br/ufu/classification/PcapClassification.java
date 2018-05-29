package br.ufu.classification;

import br.ufu.flow.model.FlowItem;
import br.ufu.pcap.model.PcapItem;
import br.ufu.pcap.parse.PcapParse;
import com.opencsv.CSVReader;
import com.opencsv.CSVWriter;
import lombok.Getter;
import lombok.Setter;
import me.tongfei.progressbar.ProgressBar;

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
    @Getter
    @Setter
    private int numberOfFlows;
    @Getter
    @Setter
    private int numberOfPackages;

    public PcapClassification(String flowFile, int numberOfFlows, String pcapFile, int numberOfPackages) {
        this.flowFile = flowFile;
        this.pcapFile = pcapFile;
        this.numberOfFlows = numberOfFlows;
        this.numberOfPackages = numberOfPackages;
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
        pcap.setTos(pcapItem[10]);
        pcap.setUrgFlag(pcapItem[11]);
        pcap.setAckFlag(pcapItem[12]);
        pcap.setPshFlag(pcapItem[13]);
        pcap.setRstFlag(pcapItem[14]);
        pcap.setSynFlag(pcapItem[15]);
        pcap.setFinFlag(pcapItem[16]);
        pcap.setFlowNumber(((pcapItem[17]).equals("")) ? 0 : Integer.parseInt(pcapItem[17]));
        pcap.setLabel(pcapItem[18]);

        return pcap;
    }

    private String inversePcap(PcapItem pcapItem) {

        return pcapItem.getDestinationAddress() + "-" + pcapItem.getDestinationPort() + "-" + pcapItem.getSourceAddress() + "-" + pcapItem.getSourcePort();
    }

    public void classification() {
        PcapItem pcapItem;
        FlowItem flowItem;

        String[] pcapLine;
        HashMap<String, LinkedList<FlowItem>> flowClassified = new HashMap<>();
        List<String> line;
        boolean firstLine;
        boolean flowFirstLine = true;
        boolean isClassified = true;
        int packageCount;
        int unclassified = 0;
        LinkedList<FlowItem> keyFlow;

        int countAttack = 0;
        int countBening = 0;

        try {
            Reader flowReader = Files.newBufferedReader(Paths.get(flowFile));
            Reader pcapReader = Files.newBufferedReader(Paths.get(pcapFile));

            CSVReader flow = new CSVReader(flowReader);
            CSVReader pcap = new CSVReader(pcapReader, ';');

            CSVWriter writer = new CSVWriter(new FileWriter(".\\file\\Pcap_Classification.csv"));

            ProgressBar progressBarFlow = new ProgressBar("Reading Flows", numberOfFlows);
            for (Iterator<String[]> it = flow.iterator(); it.hasNext(); ) {

                String[] flowIterator = it.next();

                if (flowFirstLine) {
                    flowFirstLine = false;
                    continue;
                }

                flowItem = createFlowItem(flowIterator);
                if (flowClassified.containsKey(flowItem.getKeyFlow())) {
                    keyFlow = flowClassified.get(flowItem.getKeyFlow());
                } else {
                    keyFlow = new LinkedList<>();
                }

                keyFlow.addLast(flowItem);
                flowClassified.put(flowItem.getKeyFlow(), keyFlow);

                progressBarFlow.step();

            }
            progressBarFlow.close();

            flow.close();

            packageCount = 0;

            firstLine = true;

            CSVWriter writerNoClass = new CSVWriter(new FileWriter(".\\file\\No_Pcap_Classification.csv"));
            ProgressBar progressBarPcaps = new ProgressBar("Classifying Pcaps", numberOfPackages);

            for (Iterator<String[]> it = pcap.iterator(); it.hasNext(); ) {

                pcapLine = it.next();

                if (firstLine) {
                    firstLine = false;
                    writer.writeNext(pcapLine);
                    writerNoClass.writeNext(pcapLine);
                    continue;
                }

                pcapItem = createPcapItem(pcapLine);

                if (flowClassified.containsKey(pcapItem.getFlowIdentification()) && flowClassified.get(pcapItem.getFlowIdentification()).size() != 0) {

                    if (flowClassified.get(pcapItem.getFlowIdentification()).getFirst().getTotalPackages() > 0) {
                        FlowItem item = flowClassified.get(pcapItem.getFlowIdentification()).getFirst();
                        item.updateTotalPackages();
                        flowClassified.get(pcapItem.getFlowIdentification()).size();

                        pcapItem.setLabel(item.getLabel());
                        pcapItem.setFlowNumber(item.getFlowUniqueId());

                        line = PcapParse.pcapToString(pcapItem, isClassified);

                        writer.writeNext(line.toArray(new String[line.size()]));

                        if (item.getTotalPackages() == 0) {
                            flowClassified.get(pcapItem.getFlowIdentification()).removeFirst();
                            if (!flowClassified.containsKey(pcapItem.getFlowIdentification())) {
                                flowClassified.remove(pcapItem.getFlowIdentification());
                            }
                        }
                    }
                    packageCount++;
                } else if (flowClassified.containsKey(inversePcap(pcapItem)) && flowClassified.get(inversePcap(pcapItem)).size() != 0) {

                    if (flowClassified.get(inversePcap(pcapItem)).getFirst().getTotalPackages() > 0) {
                        FlowItem item = flowClassified.get(inversePcap(pcapItem)).getFirst();
                        item.updateTotalPackages();
                        flowClassified.get(inversePcap(pcapItem)).size();

                        pcapItem.setLabel(item.getLabel());
                        pcapItem.setFlowNumber(item.getFlowUniqueId());

                        line = PcapParse.pcapToString(pcapItem, isClassified);
                        writer.writeNext(line.toArray(new String[line.size()]));

                        if (item.getTotalPackages() == 0) {
                            flowClassified.get(inversePcap(pcapItem)).removeFirst();
                            if (!flowClassified.containsKey(inversePcap(pcapItem))) {
                                flowClassified.remove(inversePcap(pcapItem));
                            }
                        }

                    }
                    packageCount++;
                } else {
                    line = PcapParse.pcapToString(pcapItem, isClassified);
                    writerNoClass.writeNext(line.toArray(new String[line.size()]));
                    unclassified++;
                }
                if (pcapItem.getLabel().equals("BENIGN")) {
                    countBening++;
                } else {

                    countAttack++;
                }
                progressBarPcaps.step();

            }

            progressBarPcaps.close();

            pcap.close();
            pcapReader.close();
            flowReader.close();

            writerNoClass.flush();
            writerNoClass.close();

            writer.flush();
            writer.close();

            System.out.println("Unclassified: " + unclassified);
            System.out.println("Flow read: " + flowClassified.size());
            System.out.println("Total of Classified Packages: " + packageCount);
            System.out.println("Class Attack: " + countAttack);
            System.out.println("Class Benning: " + countBening);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
