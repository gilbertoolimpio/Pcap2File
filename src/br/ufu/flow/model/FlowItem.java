package br.ufu.flow.model;

import lombok.Getter;
import lombok.Setter;

public class FlowItem {

    @Getter @Setter private String srcAddress;
    @Getter @Setter private String srcPort;
    @Getter @Setter private int numberSrcPackages;
    @Getter @Setter private String dstAddress;
    @Getter @Setter private String dstPort;
    @Getter @Setter private int numberDstPackages;
    @Getter @Setter private String keyFlow;
    @Getter @Setter private int flowUniqueId;
    @Getter @Setter private int totalPackages;
    @Getter @Setter private String label;


    public void updateTotalPackages(){
        this.totalPackages--;
    }

    @Override
    public String toString() {
        return "FlowItem{" +
                "srcAddress='" + srcAddress + '\'' +
                ", srcPort='" + srcPort + '\'' +
                ", numberSrcPackages=" + numberSrcPackages +
                ", dstAddress='" + dstAddress + '\'' +
                ", dstPort='" + dstPort + '\'' +
                ", numberDstPackages=" + numberDstPackages +
                ", keyFlow='" + keyFlow + '\'' +
                ", flowUniqueId=" + flowUniqueId +
                ", totalPackages=" + totalPackages +
                ", label='" + label + '\'' +
                '}';
    }
}
