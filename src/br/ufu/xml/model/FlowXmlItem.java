package br.ufu.xml.model;
import lombok.Getter;
import lombok.Setter;

import java.util.Objects;

public class FlowXmlItem {

    @Getter @Setter private String appName;
    @Getter @Setter private String totalSourceBytes;
    @Getter @Setter private String totalDestinationBytes;
    @Getter @Setter private String totalDestinationPackets;
    @Getter @Setter private String totalSourcePackets;
    @Getter @Setter private String sourcePayloadAsBase64;
    @Getter @Setter private String sourcePayloadAsUTF;
    @Getter @Setter private String destinationPayloadAsBase64;
    @Getter @Setter private String destinationPayloadAsUTF;
    @Getter @Setter private String direction;
    @Getter @Setter private String sourceTCPFlagsDescription;
    @Getter @Setter private String destinationTCPFlagsDescription;
    @Getter @Setter private String source;
    @Getter @Setter private String protocolName;
    @Getter @Setter private String sourcePort;
    @Getter @Setter private String destination;
    @Getter @Setter private String destinationPort;
    @Getter @Setter private String startDateTime;
    @Getter @Setter private String stopDateTime;
    @Getter @Setter private String Tag;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof FlowXmlItem)) return false;
        FlowXmlItem that = (FlowXmlItem) o;
        return Objects.equals(appName, that.appName) &&
                Objects.equals(totalSourceBytes, that.totalSourceBytes) &&
                Objects.equals(totalDestinationBytes, that.totalDestinationBytes) &&
                Objects.equals(totalDestinationPackets, that.totalDestinationPackets) &&
                Objects.equals(totalSourcePackets, that.totalSourcePackets) &&
                Objects.equals(sourcePayloadAsBase64, that.sourcePayloadAsBase64) &&
                Objects.equals(sourcePayloadAsUTF, that.sourcePayloadAsUTF) &&
                Objects.equals(destinationPayloadAsBase64, that.destinationPayloadAsBase64) &&
                Objects.equals(destinationPayloadAsUTF, that.destinationPayloadAsUTF) &&
                Objects.equals(direction, that.direction) &&
                Objects.equals(sourceTCPFlagsDescription, that.sourceTCPFlagsDescription) &&
                Objects.equals(destinationTCPFlagsDescription, that.destinationTCPFlagsDescription) &&
                Objects.equals(source, that.source) &&
                Objects.equals(protocolName, that.protocolName) &&
                Objects.equals(sourcePort, that.sourcePort) &&
                Objects.equals(destination, that.destination) &&
                Objects.equals(destinationPort, that.destinationPort) &&
                Objects.equals(startDateTime, that.startDateTime) &&
                Objects.equals(stopDateTime, that.stopDateTime) &&
                Objects.equals(Tag, that.Tag);
    }

    @Override
    public int hashCode() {

        return Objects.hash(appName, totalSourceBytes, totalDestinationBytes, totalDestinationPackets, totalSourcePackets, sourcePayloadAsBase64, sourcePayloadAsUTF, destinationPayloadAsBase64, destinationPayloadAsUTF, direction, sourceTCPFlagsDescription, destinationTCPFlagsDescription, source, protocolName, sourcePort, destination, destinationPort, startDateTime, stopDateTime, Tag);
    }

    @Override
    public String toString() {
        return "FlowXmlItem{" +
                "appName='" + appName + '\'' +
                ", totalSourceBytes='" + totalSourceBytes + '\'' +
                ", totalDestinationBytes='" + totalDestinationBytes + '\'' +
                ", totalDestinationPackets='" + totalDestinationPackets + '\'' +
                ", totalSourcePackets='" + totalSourcePackets + '\'' +
                ", sourcePayloadAsBase64='" + sourcePayloadAsBase64 + '\'' +
                ", sourcePayloadAsUTF='" + sourcePayloadAsUTF + '\'' +
                ", destinationPayloadAsBase64='" + destinationPayloadAsBase64 + '\'' +
                ", destinationPayloadAsUTF='" + destinationPayloadAsUTF + '\'' +
                ", direction='" + direction + '\'' +
                ", sourceTCPFlagsDescription='" + sourceTCPFlagsDescription + '\'' +
                ", destinationTCPFlagsDescription='" + destinationTCPFlagsDescription + '\'' +
                ", source='" + source + '\'' +
                ", protocolName='" + protocolName + '\'' +
                ", sourcePort='" + sourcePort + '\'' +
                ", destination='" + destination + '\'' +
                ", destinationPort='" + destinationPort + '\'' +
                ", startDateTime='" + startDateTime + '\'' +
                ", stopDateTime='" + stopDateTime + '\'' +
                ", Tag='" + Tag + '\'' +
                '}';
    }
}
