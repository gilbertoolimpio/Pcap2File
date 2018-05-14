package br.ufu.xml.parse;

import br.ufu.xml.model.FlowXmlItem;

import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

public class FlowXmlParse {

    static final String TESTBED_SUN_JUN13_FLOWS = "TestbedSunJun13Flows";
    static final String APP_NAME = "appName";
    static final String TOTAL_SOURCE_BYTES = "totalSourceBytes";
    static final String TOTAL_DESTINATION_BYTES = "totalDestinationBytes";
    static final String TOTAL_DESTINATION_PACKETS = "totalDestinationPackets";
    static final String TOTAL_SOURCE_PACKETS = "totalSourcePackets";
    static final String SOURCE_PAYLOAD_AS_BASE64 = "sourcePayloadAsBase64";
    static final String SOURCE_PAYLOAD_AS_UTF = "sourcePayloadAsUTF";
    static final String DESTINATION_PAYLOAD_AS_BASE64 = "destinationPayloadAsBase64";
    static final String DESTINATION_PAYLOAD_AS_UTF = "destinationPayloadAsUTF";
    static final String DIRECTION = "direction";
    static final String SOURCE_TCP_FLAGS_DESCRIPTION = "sourceTCPFlagsDescription";
    static final String DESTINATION_TCP_FLAGS_DESCRIPTION = "destinationTCPFlagsDescription";
    static final String SOURCE = "source";
    static final String PROTOCOL_NAME = "protocolName";
    static final String SOURCE_PORT = "sourcePort";
    static final String DESTINATION = "destination";
    static final String DESTINATION_PORT = "destinationPort";
    static final String START_DATE_TIME = "startDateTime";
    static final String STOP_DATE_TIME = "stopDateTime";
    static final String TAG = "Tag";


    public List<FlowXmlItem> readXmlFlow(String xmlFlowFile) {

        List<FlowXmlItem> flowXmlItems = new ArrayList<>();

        try {
            XMLInputFactory inputFactory = XMLInputFactory.newInstance();
            InputStream inputStream = new FileInputStream(xmlFlowFile);
            XMLEventReader eventReader = inputFactory.createXMLEventReader(inputStream);
            FlowXmlItem flowXmlItem = null;

            while (eventReader.hasNext()) {
                XMLEvent xmlEvent = eventReader.nextEvent();

                if (xmlEvent.isStartElement()) {
                    StartElement startElement = xmlEvent.asStartElement();
                    if (startElement.getName().getLocalPart().equals(TESTBED_SUN_JUN13_FLOWS)) {
                        flowXmlItem = new FlowXmlItem();
                    }
                    if (xmlEvent.isStartElement()) {
                        if (xmlEvent.asStartElement().getName().getLocalPart().equals(APP_NAME)) {
                            xmlEvent = eventReader.nextEvent();
                            if (xmlEvent.isEndElement()) {
                                flowXmlItem.setAppName("");
                                continue;
                            }
                            flowXmlItem.setAppName(xmlEvent.asCharacters().getData());
                            continue;
                        }
                    }
                    if (xmlEvent.isStartElement()) {
                        if (xmlEvent.asStartElement().getName().getLocalPart().equals(TOTAL_SOURCE_BYTES)) {
                            xmlEvent = eventReader.nextEvent();
                            if (xmlEvent.isEndElement()) {
                                flowXmlItem.setTotalSourceBytes("");
                                continue;
                            }
                            flowXmlItem.setTotalSourceBytes(xmlEvent.asCharacters().getData());
                            continue;
                        }
                    }
                    if (xmlEvent.isStartElement()) {
                        if (xmlEvent.asStartElement().getName().getLocalPart().equals(TOTAL_DESTINATION_BYTES)) {
                            xmlEvent = eventReader.nextEvent();
                            if (xmlEvent.isEndElement()) {
                                flowXmlItem.setTotalDestinationBytes("");
                                continue;
                            }
                            flowXmlItem.setTotalDestinationBytes(xmlEvent.asCharacters().getData());
                            continue;
                        }
                    }
                    if (xmlEvent.isStartElement()) {
                        if (xmlEvent.asStartElement().getName().getLocalPart().equals(TOTAL_DESTINATION_PACKETS)) {
                            xmlEvent = eventReader.nextEvent();
                            if (xmlEvent.isEndElement()) {
                                flowXmlItem.setTotalDestinationPackets("");
                                continue;
                            }
                            flowXmlItem.setTotalDestinationPackets(xmlEvent.asCharacters().getData());
                            continue;
                        }
                    }
                    if (xmlEvent.isStartElement()) {
                        if (xmlEvent.asStartElement().getName().getLocalPart().equals(TOTAL_SOURCE_PACKETS)) {
                            xmlEvent = eventReader.nextEvent();
                            if (xmlEvent.isEndElement()) {
                                flowXmlItem.setTotalSourcePackets("");
                                continue;
                            }
                            flowXmlItem.setTotalSourcePackets(xmlEvent.asCharacters().getData());
                            continue;
                        }
                    }
                    if (xmlEvent.isStartElement()) {
                        if (xmlEvent.asStartElement().getName().getLocalPart().equals(SOURCE_PAYLOAD_AS_BASE64)) {
                            xmlEvent = eventReader.nextEvent();
                            if (xmlEvent.isEndElement()) {
                                flowXmlItem.setSourcePayloadAsBase64("");
                                continue;
                            }
                            flowXmlItem.setSourcePayloadAsBase64(xmlEvent.asCharacters().getData());
                            continue;
                        }
                    }
                    if (xmlEvent.isStartElement()) {
                        if (xmlEvent.asStartElement().getName().getLocalPart().equals(SOURCE_PAYLOAD_AS_UTF)) {
                            xmlEvent = eventReader.nextEvent();
                            if (xmlEvent.isEndElement()) {
                                flowXmlItem.setSourcePayloadAsUTF("");
                                continue;
                            }
                            flowXmlItem.setSourcePayloadAsUTF(xmlEvent.asCharacters().getData());
                            continue;
                        }
                    }
                    if (xmlEvent.isStartElement()) {
                        if (xmlEvent.asStartElement().getName().getLocalPart().equals(DESTINATION_PAYLOAD_AS_BASE64)) {
                            xmlEvent = eventReader.nextEvent();
                            if (xmlEvent.isEndElement()) {
                                flowXmlItem.setDestinationPayloadAsBase64("");
                                continue;
                            }
                            flowXmlItem.setDestinationPayloadAsBase64(xmlEvent.asCharacters().getData());
                            continue;
                        }
                    }
                    if (xmlEvent.isStartElement()) {
                        if (xmlEvent.asStartElement().getName().getLocalPart().equals(DESTINATION_PAYLOAD_AS_UTF)) {
                            xmlEvent = eventReader.nextEvent();
                            if (xmlEvent.isEndElement()) {
                                flowXmlItem.setDestinationPayloadAsUTF("");
                                continue;
                            }

                            flowXmlItem.setDestinationPayloadAsUTF(xmlEvent.asCharacters().getData());
                            continue;
                        }
                    }
                    if (xmlEvent.isStartElement()) {
                        if (xmlEvent.asStartElement().getName().getLocalPart().equals(DIRECTION)) {
                            xmlEvent = eventReader.nextEvent();
                            if (xmlEvent.isEndElement()) {
                                flowXmlItem.setDirection("");
                                continue;
                            }

                            flowXmlItem.setDirection(xmlEvent.asCharacters().getData());
                            continue;
                        }
                    }
                    if (xmlEvent.isStartElement()) {
                        if (xmlEvent.asStartElement().getName().getLocalPart().equals(SOURCE_TCP_FLAGS_DESCRIPTION)) {
                            xmlEvent = eventReader.nextEvent();
                            if (xmlEvent.isEndElement()) {
                                flowXmlItem.setSourceTCPFlagsDescription("");
                                continue;
                            }

                            flowXmlItem.setSourceTCPFlagsDescription(xmlEvent.asCharacters().getData());
                            continue;
                        }
                    }
                    if (xmlEvent.isStartElement()) {
                        if (xmlEvent.asStartElement().getName().getLocalPart().equals(DESTINATION_TCP_FLAGS_DESCRIPTION)) {
                            xmlEvent = eventReader.nextEvent();
                            if (xmlEvent.isEndElement()) {
                                flowXmlItem.setDestinationTCPFlagsDescription("");
                                continue;
                            }

                            flowXmlItem.setDestinationTCPFlagsDescription(xmlEvent.asCharacters().getData());
                            continue;
                        }
                    }
                    if (xmlEvent.isStartElement()) {
                        if (xmlEvent.asStartElement().getName().getLocalPart().equals(SOURCE)) {
                            xmlEvent = eventReader.nextEvent();
                            if (xmlEvent.isEndElement()) {
                                flowXmlItem.setSource("");
                                continue;
                            }

                            flowXmlItem.setSource(xmlEvent.asCharacters().getData());
                            continue;
                        }
                    }
                    if (xmlEvent.isStartElement()) {
                        if (xmlEvent.asStartElement().getName().getLocalPart().equals(PROTOCOL_NAME)) {
                            xmlEvent = eventReader.nextEvent();
                            if (xmlEvent.isEndElement()) {
                                flowXmlItem.setProtocolName("");
                                continue;
                            }

                            flowXmlItem.setProtocolName(xmlEvent.asCharacters().getData());
                            continue;
                        }
                    }
                    if (xmlEvent.isStartElement()) {
                        if (xmlEvent.asStartElement().getName().getLocalPart().equals(SOURCE_PORT)) {
                            xmlEvent = eventReader.nextEvent();
                            if (xmlEvent.isEndElement()) {
                                flowXmlItem.setSourcePort("");
                                continue;
                            }

                            flowXmlItem.setSourcePort(xmlEvent.asCharacters().getData());
                            continue;
                        }
                    }
                    if (xmlEvent.isStartElement()) {
                        if (xmlEvent.asStartElement().getName().getLocalPart().equals(DESTINATION)) {
                            xmlEvent = eventReader.nextEvent();
                            if (xmlEvent.isEndElement()) {
                                flowXmlItem.setDestination("");
                                continue;
                            }

                            flowXmlItem.setDestination(xmlEvent.asCharacters().getData());
                            continue;
                        }
                    }
                    if (xmlEvent.isStartElement()) {
                        if (xmlEvent.asStartElement().getName().getLocalPart().equals(DESTINATION_PORT)) {
                            xmlEvent = eventReader.nextEvent();
                            if (xmlEvent.isEndElement()) {
                                flowXmlItem.setDestinationPort("");
                                continue;
                            }

                            flowXmlItem.setDestinationPort(xmlEvent.asCharacters().getData());
                            continue;
                        }
                    }
                    if (xmlEvent.isStartElement()) {
                        if (xmlEvent.asStartElement().getName().getLocalPart().equals(START_DATE_TIME)) {
                            xmlEvent = eventReader.nextEvent();
                            if (xmlEvent.isEndElement()) {
                                flowXmlItem.setStartDateTime("");
                                continue;
                            }

                            flowXmlItem.setStartDateTime(xmlEvent.asCharacters().getData());
                            continue;
                        }
                    }
                    if (xmlEvent.isStartElement()) {
                        if (xmlEvent.asStartElement().getName().getLocalPart().equals(STOP_DATE_TIME)) {
                            xmlEvent = eventReader.nextEvent();
                            if (xmlEvent.isEndElement()) {
                                flowXmlItem.setStopDateTime("");
                                continue;
                            }

                            flowXmlItem.setStopDateTime(xmlEvent.asCharacters().getData());
                            continue;
                        }
                    }
                    if (xmlEvent.isStartElement()) {
                        if (xmlEvent.asStartElement().getName().getLocalPart().equals(TAG)) {
                            xmlEvent = eventReader.nextEvent();
                            if (xmlEvent.isEndElement()) {
                                flowXmlItem.setTag("");
                                continue;
                            }

                            flowXmlItem.setTag(xmlEvent.asCharacters().getData());
                            continue;
                        }
                    }
                }
                if (xmlEvent.isEndElement()) {
                    EndElement endElement = xmlEvent.asEndElement();
                    if (endElement.getName().getLocalPart().equals(TESTBED_SUN_JUN13_FLOWS)) {
                        flowXmlItems.add(flowXmlItem);
                    }
                }

            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (XMLStreamException e) {
            e.printStackTrace();
        }
        return flowXmlItems;
    }
}
