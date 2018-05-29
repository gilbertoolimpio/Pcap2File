import br.ufu.classification.ArffGenerator;
import br.ufu.pcap.parse.PcapParse;

import java.io.IOException;


public class PcapMain {
    public static void main(String args[]) throws IOException {

        String pcapFile = ".\\file\\New_wednesday.pcap";
        PcapParse pcapParse = new PcapParse();
        try {
            //        pcapParse.readPcapFile(pcapFile);

            //Flows: 692704
            //Pcaps: 13781343

/*            PcapClassification classification = new PcapClassification(
                    "D:\\Arquivos Mestrado\\file\\Wednesday-workingHours.pcap_ISCX_NEW.csv",
                    692703,
                    "D:\\Arquivos Mestrado\\file\\New_wednesday.csv",
                    13781343);


            //Pcaps = 13781343
            //classification.classification(pcapParse.getCountPackage());
            classification.classification();*/

            //   ArffGenerator.createPackageArff(".\\file\\Pcap_Classification.csv");

            ArffGenerator.createFlowArff("D:\\Arquivos Mestrado\\file\\Wednesday-workingHours.pcap_ISCX_NEW.csv");

/*
        } catch (PcapNativeException e) {
            e.printStackTrace();
        } catch (NotOpenException e) {
            e.printStackTrace();
*/
        } finally {

        }
    }
}

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