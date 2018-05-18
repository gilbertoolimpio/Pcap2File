package br.ufu.pcap.model;

import lombok.Getter;
import lombok.Setter;

public class PcapItem {

    @Getter @Setter private int idPackage;
    @Getter @Setter private String flowIdentification;
    @Getter @Setter private String sourceAddress;
    @Getter @Setter private String sourcePort;
    @Getter @Setter private String destinationAddress;
    @Getter @Setter private String destinationPort;
    @Getter @Setter private String protocol;
    @Getter @Setter private int packageTotalLenght;
    @Getter @Setter private int headerLenght;
    @Getter @Setter private String packageTimestamp;
    @Getter @Setter private String urgFlag;
    @Getter @Setter private String ackFlag;
    @Getter @Setter private String pshFlag;
    @Getter @Setter private String rstFlag;
    @Getter @Setter private String synFlag;
    @Getter @Setter private String finFlag;
    @Getter @Setter private int flowNumber;
    @Getter @Setter private String label;

    @Override
    public String toString() {
        return "PcapItem{" +
                "idPackage=" + idPackage +
                ", flowIdentification='" + flowIdentification + '\'' +
                ", sourceAddress='" + sourceAddress + '\'' +
                ", sourcePort='" + sourcePort + '\'' +
                ", destinationAddress='" + destinationAddress + '\'' +
                ", destinationPort='" + destinationPort + '\'' +
                ", protocol='" + protocol + '\'' +
                ", packageTotalLenght=" + packageTotalLenght +
                ", headerLenght=" + headerLenght +
                ", packageTimestamp='" + packageTimestamp + '\'' +
                ", urgFlag='" + urgFlag + '\'' +
                ", ackFlag='" + ackFlag + '\'' +
                ", pshFlag='" + pshFlag + '\'' +
                ", rstFlag='" + rstFlag + '\'' +
                ", synFlag='" + synFlag + '\'' +
                ", finFlag='" + finFlag + '\'' +
                ", flowNumber=" + flowNumber +
                ", label='" + label + '\'' +
                '}';
    }
}
