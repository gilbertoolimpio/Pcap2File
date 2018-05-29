package br.ufu.classification;

import com.opencsv.CSVReader;
import lombok.Getter;
import lombok.Setter;
import me.tongfei.progressbar.ProgressBar;

import java.io.FileWriter;
import java.io.IOException;
import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Iterator;

public class ArffGenerator {


    @Getter
    @Setter
    private int sourcePort;
    @Getter
    @Setter
    private int destinationPort;
    @Getter
    @Setter
    private String protocol;
    @Getter
    @Setter
    private int packageTotalLenght;
    @Getter
    @Setter
    private int headerLenght;
    @Getter
    @Setter
    private String urgFlag;
    @Getter
    @Setter
    private String ackFlag;
    @Getter
    @Setter
    private String pshFlag;
    @Getter
    @Setter
    private String rstFlag;
    @Getter
    @Setter
    private String synFlag;
    @Getter
    @Setter
    private String finFlag;
    @Getter
    @Setter
    private String label;


    public static void createPackageArff(String pcapFile) {
        FileWriter fileWriter = null;
        boolean firstLine = true;

        try {
            fileWriter = new FileWriter(".\\file\\Pcaps_to_MOA.arff");

            Reader reader = Files.newBufferedReader(Paths.get(pcapFile));
            CSVReader csvReader = new CSVReader(reader);

            fileWriter.write("@RELATION " + "pcaps_classification\n" );


            fileWriter.write("@ATTRIBUTE " + "sourcePort" + " NUMERIC\n");
            fileWriter.write("@ATTRIBUTE " + "destinationPort" + " NUMERIC\n");
            fileWriter.write("@ATTRIBUTE " + "protocol" + " {tcp_ip, udp_ip, na}\n");
            fileWriter.write("@ATTRIBUTE " + "packageTotalLenght" + " NUMERIC\n");
            fileWriter.write("@ATTRIBUTE " + "headerLenght" + " NUMERIC\n");
            fileWriter.write("@ATTRIBUTE " + "urgFlag" + " {true, false, na}\n");
            fileWriter.write("@ATTRIBUTE " + "ackFlag" + " {true, false, na}\n");
            fileWriter.write("@ATTRIBUTE " + "pshFlag" + " {true, false, na}\n");
            fileWriter.write("@ATTRIBUTE " + "rstFlag" + " {true, false, na}\n");
            fileWriter.write("@ATTRIBUTE " + "synFlag" + " {true, false, na}\n");
            fileWriter.write("@ATTRIBUTE " + "finFlag" + " {true, false, na}\n");
            fileWriter.write("@ATTRIBUTE " + "label" + " {BENIGN, ATTACK, na}\n");


            fileWriter.write("@Data\n");

            ProgressBar progressBar = new ProgressBar("Create ARFF", 13657907);
            for (Iterator<String[]> it = csvReader.iterator(); it.hasNext(); ) {
                String[] line = it.next();

                if (firstLine){
                    firstLine = false;
                    continue;
                }


                fileWriter.write(line[3] + "," +
                        line[5] + "," +
                        line[6] + "," +
                        line[7] + "," +
                        line[8] + "," +
                        line[11] + "," +
                        line[12] + "," +
                        line[13] + "," +
                        line[14] + "," +
                        line[15] + "," +
                        line[16] + "," +
                        line[18] + "\n");

                progressBar.step();
            }
            progressBar.close();
            fileWriter.flush();
            fileWriter.close();

/*
            0 header.add("idPackage");
            1 header.add("flowIdentification");
            2 header.add("sourceAddress");
            3 header.add("sourcePort");*
            4 header.add("destinationAddress");
            5 header.add("destinationPort");*
            6 header.add("protocol");*
            7 header.add("packageTotalLenght")*;
            8 header.add("headerLenght")*;
            9 header.add("packageTimestamp");
            10 header.add("tos");
            11 header.add("urgFlag")*;
            12 header.add("ackFlag")*;
            13 header.add("pshFlag")*;
            14 header.add("rstFlag")*;
            15 header.add("synFlag")*;
            16 header.add("finFlag")*;
            17 header.add("flowNumber");
            18 header.add("label")*;
* */


        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    public static void createFlowArff(String flowFile) {
        FileWriter fileWriter = null;
        boolean firstLine = true;

        try {
            fileWriter = new FileWriter(".\\file\\Flows_to_MOA.arff");

            Reader reader = Files.newBufferedReader(Paths.get(flowFile));
            CSVReader csvReader = new CSVReader(reader);

            fileWriter.write("@RELATION " + "flows_classification\n" );


            fileWriter.write("@ATTRIBUTE " + "SourcePort" + " NUMERIC\n");
            fileWriter.write("@ATTRIBUTE " + "DestinationPort" + " NUMERIC\n");
            fileWriter.write("@ATTRIBUTE " + "Protocol" + " NUMERIC\n");
            fileWriter.write("@ATTRIBUTE " + "FlowDuration" + " NUMERIC\n");
            fileWriter.write("@ATTRIBUTE " + "TotalFwdPackets" + " NUMERIC\n");
            fileWriter.write("@ATTRIBUTE " + "TotalBackwardPackets" + " NUMERIC\n");
            fileWriter.write("@ATTRIBUTE " + "TotalLengthofFwdPackets" + " NUMERIC\n");
            fileWriter.write("@ATTRIBUTE " + "TotalLengthofBwdPackets" + " NUMERIC\n");
            fileWriter.write("@ATTRIBUTE " + "FwdPacketLengthMax" + " NUMERIC\n");
            fileWriter.write("@ATTRIBUTE " + "FwdPacketLengthMin" + " NUMERIC\n");
            fileWriter.write("@ATTRIBUTE " + "BwdPacketLengthMax" + " NUMERIC\n");
            fileWriter.write("@ATTRIBUTE " + "BwdPacketLengthMin" + " NUMERIC\n");
            fileWriter.write("@ATTRIBUTE " + "FINFlagCount" + " NUMERIC\n");
            fileWriter.write("@ATTRIBUTE " + "SYNFlagCount" + " NUMERIC\n");
            fileWriter.write("@ATTRIBUTE " + "RSTFlagCount" + " NUMERIC\n");
            fileWriter.write("@ATTRIBUTE " + "PSHFlagCount" + " NUMERIC\n");
            fileWriter.write("@ATTRIBUTE " + "ACKFlagCount" + " NUMERIC\n");
            fileWriter.write("@ATTRIBUTE " + "URGFlagCount" + " NUMERIC\n");
            fileWriter.write("@ATTRIBUTE " + "CWEFlagCount" + " NUMERIC\n");
            fileWriter.write("@ATTRIBUTE " + "ECEFlagCount" + " NUMERIC\n");
            fileWriter.write("@ATTRIBUTE " + "DownUpRatio" + " NUMERIC\n");
            fileWriter.write("@ATTRIBUTE " + "{BENIGN, ATTACK, na}" + " NUMERIC\n");



            fileWriter.write("@Data\n");

            ProgressBar progressBar = new ProgressBar("Create ARFF", 13657907);
            for (Iterator<String[]> it = csvReader.iterator(); it.hasNext(); ) {
                String[] line = it.next();

                if (firstLine){
                    firstLine = false;
                    continue;
                }


                fileWriter.write(line[2] + "," +
                        line[4] + "," +
                        line[5] + "," +
                        line[7] + "," +
                        line[8] + "," +
                        line[9] + "," +
                        line[10] + "," +
                        line[11] + "," +
                        line[12] + "," +
                        line[13] + "," +
                        line[16] + "," +
                        line[17] + "," +
                        line[49] + "," +
                        line[50] + "," +
                        line[51] + "," +
                        line[52] + "," +
                        line[53] + "," +
                        line[54] + "," +
                        line[55] + "," +
                        line[56] + "," +
                        line[57] + "," +
                        (line[84].equals("BENIGN") ? line[84]+ "\n" : "ATTACK" + "\n"));

                progressBar.step();
            }
            progressBar.close();
            fileWriter.flush();
            fileWriter.close();

/*
            0 header.add("idPackage");
            1 header.add("flowIdentification");
            2 header.add("sourceAddress");
            3 header.add("sourcePort");*
            4 header.add("destinationAddress");
            5 header.add("destinationPort");*
            6 header.add("protocol");*
            7 header.add("packageTotalLenght")*;
            8 header.add("headerLenght")*;
            9 header.add("packageTimestamp");
            10 header.add("tos");
            11 header.add("urgFlag")*;
            12 header.add("ackFlag")*;
            13 header.add("pshFlag")*;
            14 header.add("rstFlag")*;
            15 header.add("synFlag")*;
            16 header.add("finFlag")*;
            17 header.add("flowNumber");
            18 header.add("label")*;
* */


        } catch (IOException e) {
            e.printStackTrace();
        }

    }

}
