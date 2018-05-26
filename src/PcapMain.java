import br.ufu.classification.PcapClassification;
import br.ufu.pcap.model.PcapItem;
import br.ufu.pcap.parse.PcapParse;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@SuppressWarnings("deprecation")
public class PcapMain {
    public static void main(String args[]) throws IOException {

        String pcapFile = ".\\file\\New_wednesday.pcap";
        PcapParse pcapParse = new PcapParse();
        try {
            pcapParse.readPcapFile(pcapFile);

            //Flows: 692704
            //Pcaps: 13781343
            PcapClassification classification = new PcapClassification(
                    ".\\file\\Wednesday-workingHours.pcap_ISCX_NEW.csv",
                    692703,
                    ".\\file\\New_wednesday.csv",
                    13781343);

            //Pcaps = 13781343
            //classification.classification(pcapParse.getCountPackage());
            classification.classification();
        } catch (PcapNativeException e) {
            e.printStackTrace();
        } catch (NotOpenException e) {
            e.printStackTrace();
        }finally {

        }
    }
}
