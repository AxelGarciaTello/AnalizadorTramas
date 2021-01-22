import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.io.*;
import javax.swing.JFileChooser;
import javax.swing.filechooser.FileNameExtensionFilter;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapAddr;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.tcpip.*;
import org.jnetpcap.protocol.network.*;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.lan.IEEE802dot2;
import org.jnetpcap.protocol.lan.IEEE802dot3;


public class Captura {

    private static String asString(final byte[] mac) {
        final StringBuilder buf = new StringBuilder();
        for (byte b : mac) {
            if (buf.length() != 0) {
                buf.append(':');
            }
            if (b >= 0 && b < 16) {
                buf.append('0');
            }
            buf.append(Integer.toHexString((b < 0) ? b + 256 : b).toUpperCase());
        }
        return buf.toString();
    }

    public static void definirTipoTrama(int tipo, PcapPacket packet){
        String mensaje="";
        boolean bandera=true;
        if(tipo<=1500){
            mensaje="Trama IEEE802.3 Length Field";
        }
        else if(tipo>=2184 && tipo<=2186){
            mensaje="Xyplex";
        }
        else if(tipo>=4097 && tipo<=4111){
            mensaje="Berkeley Trailer encap/IP";
        }
        else if(tipo==24584 || tipo==24585){
            mensaje="DEC Unassigned";
        }
        else if(tipo>=24586 && tipo<=24596){
            mensaje="3Com Corporation";
        }
        else if(tipo>=28704 && tipo<=28713){
            mensaje="LRT";
        }
        else if(tipo>=32825 && tipo<=32828){
            mensaje="DEC Unassigned";
        }
        else if(tipo>=32832 && tipo<=32834){
            mensaje="DEC Unassigned";
        }
        else if(tipo==32869 || tipo==32870){
            mensaje="Univ. of Mass. @ Amherst";
        }
        else if(tipo>=32878 && tipo<=32887){
            mensaje="Landmark Graphics Corp.";
        }
        else if(tipo>=32893 && tipo<=31895){
            mensaje="Vitalink Communications";
        }
        else if(tipo>=32897 && tipo<=32899){
            mensaje="Counterpoint Computers";
        }
        else if(tipo>=32924 && tipo<=32926){
            mensaje="Datability";
        }
        else if(tipo>=32932 && tipo<=32947){
            mensaje="Siemens Gammasonics Inc.";
        }
        else if(tipo>=32960 && tipo<=32963){
            mensaje="DCA Data Exchange Cluster";
        }
        else if(tipo>=32968 && tipo<=32972){
            mensaje="Intergraph Corporation";
        }
        else if(tipo==32973 || tipo==32974){
            mensaje="Harris Corporation";
        }
        else if(tipo>=32975 && tipo<=32978){
            mensaje="Taylor Instrument";
        }
        else if(tipo>=32979 && tipo<=32980){
            mensaje="Rosemount Corporation";
        }
        else if(tipo==32990 || tipo==32991){
            mensaje="Integrated Solutions TRFS";
        }
        else if(tipo>=32992 && tipo<=32995){
            mensaje="Allen-Bradley";
        }
        else if(tipo>=32996 && tipo<=33008){
            mensaje="Datability";
        }
        else if(tipo==33012 || tipo==33013){
            mensaje="Kinetics";
        }
        else if(tipo>=33023 && tipo<=33027){
            mensaje="Wellfleet Communications";
        }
        else if(tipo>=33031 && tipo<=33033){
            mensaje="Symbolics Private";
        }
        else if(tipo==33079 || tipo==33080){
            mensaje="Novell, Inc.";
        }
        else if(tipo>=33081 && tipo<=33085){
            mensaje="KTI";
        }
        else{
            switch(tipo){
                case 1536: mensaje="XEROX NS IDP";
                break;
                case 2048: System.out.println("\n\t|-->Tipo de trama: IPv4"); /*Potocolo IP*/
                           analizarProtocoloIP(packet);
                           bandera=false;
                break;
                case 2049: mensaje="X.75 Internet";
                break;
                case 2050: mensaje="NBS Internet";
                break;
                case 2051: mensaje="ECMA Internet";
                break;
                case 2052: mensaje="Chaosnet";
                break;
                case 2053: mensaje="X.25 Level 3";
                break;
                case 2054: System.out.println("\n\t|-->Subtipo de trama: ARP");
                           analizarProtocoloARP(packet);
                           bandera=false;
                break;
                case 2055: mensaje="XNS Compatability";
                break;
                case 2076: mensaje="Symbolics Private";
                break;
                case 2304: mensaje="Ungermann-Bass net debugr";
                break;
                case 2560: mensaje="Xerox IEEE802.3 PUP";
                break;
                case 2561: mensaje="PUP Addr Trans";
                break;
                case 2989: mensaje="Banyan Systems";
                break;
                case 4096: mensaje="Berkeley Trailer nego";
                break;
                case 5632: mensaje="Valid Systems";
                break;
                case 16962: mensaje="PCS Basic Block Protocol";
                break;
                case 21000: mensaje="BBN Simnet";
                break;
                case 24576: mensaje="DEC Unassigned (Exp.)";
                break;
                case 24577: mensaje="DEC MOP Dump/Load";
                break;
                case 24578: mensaje="DEC MOP Remote Console";
                break;
                case 24579: mensaje="DEC DECNET Phase IV Route";
                break;
                case 24580: mensaje="DEC LAT";
                break;
                case 24581: mensaje="DEC Diagnostic Protocol";
                break;
                case 24582: mensaje="DEC Customer Protocol";
                break;
                case 24583: mensaje="DEC LAVC, SCA";
                break;
                case 28672: mensaje="Ungermann-Bass download";
                break;
                case 28674: mensaje="Ungermann-Bass dia/loop";
                break;
                case 28720: mensaje="Proteon";
                break;
                case 28724: mensaje="Cabletron";
                break;
                case 32771: mensaje="Cronus VLN";
                break;
                case 32772: mensaje="Cronus Direct";
                break;
                case 32773: mensaje="HP Probe";
                break;
                case 32774: mensaje="Nestar";
                break;
                case 32776: mensaje="AT&T";
                break;
                case 32784: mensaje="Excelan";
                break;
                case 32787: mensaje="SGI diagnostics";
                break;
                case 32788: mensaje="SGI network games";
                break;
                case 32789: mensaje="SGI reserved";
                break;
                case 32790: mensaje="SGI bounce server";
                break;
                case 32793: mensaje="Apollo Computers";
                break;
                case 32815: mensaje="Tymshare";
                break;
                case 32816: mensaje="Tigan, Inc.";
                break;
                case 32821: mensaje="Reverse ARP";
                break;
                case 32822: mensaje="Aeonic Systems";
                break;
                case 32824: mensaje="DEC LANBridge";
                break;
                case 32829: mensaje="DEC Ethernet Encryption";
                break;
                case 32830: mensaje="DEC Unassigned";
                break;
                case 32831: mensaje="DEC LAN Traffic Monitor";
                break;
                case 32836: mensaje="Planning Research Corp.";
                break;
                case 32838: mensaje="AT&T";
                break;
                case 32839: mensaje="AT&T";
                break;
                case 32841: mensaje="ExperData";
                break;
                case 32859: mensaje="Stanford V Kernel exp.";
                break;
                case 32860: mensaje="Stanford V Kernel prod.";
                break;
                case 32861: mensaje="Evans & Sutherland";
                break;
                case 32864: mensaje="Little Machines";
                break;
                case 32866: mensaje="Counterpoint Computers";
                break;
                case 32871: mensaje="Veeco Integrated Auto.";
                break;
                case 32872: mensaje="General Dynamics";
                break;
                case 32873: mensaje="AT&T";
                break;
                case 32874: mensaje="Autophon";
                break;
                case 32876: mensaje="ComDesign";
                break;
                case 32877: mensaje="Computgraphic Corp.";
                break;
                case 32890: mensaje="Matra";
                break;
                case 32891: mensaje="Dansk Data Elektronik";
                break;
                case 32892: mensaje="Merit Internodal";
                break;
                case 32896: mensaje="Vitalink TransLAN III";
                break;
                case 32923: mensaje="Appletalk";
                break;
                case 32927: mensaje="Spider Systems Ltd.";
                break;
                case 32931: mensaje="Nixdorf Computers";
                break;
                case 32966: mensaje="Pacer Software";
                break;
                case 32967: mensaje="Applitek Corporation";
                break;
                case 32981: mensaje="IBM SNA Service on Ether";
                break;
                case 32989: mensaje="Varian Associates";
                break;
                case 33010: mensaje="Retix";
                break;
                case 33011: mensaje="AppleTalk AARP (Kinetics)";
                break;
                case 33015: mensaje="Apollo Computer";
                break;
                case 33072: mensaje="Waterloo Microsystemsr";
                break;
                case 33073: mensaje="VG Laboratory Systems";
                break;
                case 33100: mensaje="SNMP";
                break;
                case 36864: mensaje="Loopback";
                break;
                case 36865: mensaje="3Com(Bridge) XNS Sys Mgmt";
                break;
                case 36866: mensaje="3Com(Bridge) TCP-IP Sys";
                break;
                case 36867: mensaje="3Com(Bridge) loop detect";
                break;
                case 65280: mensaje="BBN VITAL-LanBridge cache";
                break;
                default: mensaje="Tipo de trama desconocido";
                break;
            }
        }
        if (bandera){
            System.out.println("\n\t|-->Subtipo de trama: "+mensaje);
        }
    }

    public static void identificarProtocolo(int sap){
        String mensaje="Procolo: ";
        if(sap==4 || sap==5 || sap==8 || sap==12){
            mensaje+="SNA";
        }
        else if(sap==248 || sap==252){
            mensaje+="RPL";
        }
        else if(sap==240 || sap==241){
            mensaje+="NetBios";
        }
        else{
            switch(sap){
                case 0: mensaje+="NULL SAP";
                break;
                case 6: mensaje+="TCP";
                break;
                case 66: mensaje+="Spanning Tree";
                break;
                case 127: mensaje+="ISO 802.2";
                break;
                case 128: mensaje+="XNS";
                break;
                case 170: mensaje+="SNAP";
                break;
                case 224: mensaje+="IPX";
                break;
                case 254: mensaje+="OSI";
                break;
                case 255: mensaje+="Global SAP";
                break;
                default: mensaje+="otros";
                break;
            }
        }
        System.out.println("\t"+mensaje);
    }

    public static void identificarCampoControl(int longitud,PcapPacket packet){
        int trama=0,
            tipo=0,
            Ns=0,
            pf=0,
            Nr=0,
            codigo=0;
        String mensaje="";
        System.out.println("-------------------------------------------------");
        System.out.println("Información de la trama");
        if(longitud<=3){
            trama=packet.getUByte(16);
            tipo=trama & 0x00000001;
            if(tipo==0){
                System.out.println("\tTrama I");
                trama=trama>>1;
                Ns=trama & 0x00000111;
                System.out.println("\tN(S): "+Ns);
                trama=trama>>3;
                pf=trama & 0x00000001;
                trama=trama>>1;
                Nr=trama & 0x00000111;
                System.out.println("\tN(R): "+Nr);
                if(pf==0){
                    System.out.println("\tSondeo");
                }
                else{
                    System.out.println("\tBit final");
                }
            }
            else{
                trama=trama>>1;
                tipo=trama & 0x00000001;
                if(tipo==0){
                    System.out.println("\tTrama S");
                    trama=trama>>1;
                    codigo=trama & 0x00000011;
                    switch(codigo){
                        case 0: mensaje="Listo para recibir (RR)";
                        break;
                        case 1: mensaje="Rechazo (REJ)";
                        break;
                        case 2: mensaje="Receptor no listo para recibir (RNR)";
                        break;
                        case 3: mensaje="Rechazo selectivo (SREJ)";
                        break;
                    }
                    System.out.println("\tCódigo: "+mensaje);
                    trama=trama>>2;
                    pf=trama & 0x00000001;
                    trama=trama>>1;
                    Nr=trama & 0x00000111;
                    System.out.println("\tN(R): "+Nr);
                    if(pf==0){
                        System.out.println("\tSondeo");
                    }
                    else{
                        System.out.println("\tBit final");
                    }
                }
                else{
                    System.out.println("\tTrama U");
                    trama=trama>>1;
                    codigo=(trama & 0x00000001)<<4;
                    trama=trama>>1;
                    codigo+=(trama & 0x00000001)<<3;
                    trama=trama>>1;
                    pf=trama & 0x00000001;
                    trama=trama>>1;
                    codigo+=(trama & 0x00000001)<<2;
                    trama=trama>>1;
                    codigo+=(trama & 0x00000001)<<1;
                    trama=trama>>1;
                    codigo+=trama & 0x00000001;
                    switch(codigo){
                        case 1: mensaje="SNRM";
                        break;
                        case 27: mensaje="SNRME";
                        break;
                        case 28: mensaje="SABM";
                        break;
                        case 30: mensaje="SABME";
                        break;
                        case 0: mensaje="UI";
                        break;
                        case 6: mensaje="Reconocimiento sin númerar";
                        break;
                        case 2: mensaje="DISC";
                        break;
                        case 16: mensaje="SIM";
                        break;
                        case 4: mensaje="UP";
                        break;
                        case 25: mensaje="RSET";
                        break;
                        case 29: mensaje="XID";
                        break;
                        case 17: mensaje="FRMR";
                        break;
                        default: mensaje="desconocido";
                        break;
                    }
                    System.out.println("\tComando: "+mensaje);
                    if(pf==0){
                        System.out.println("\tSondeo");
                    }
                    else{
                        System.out.println("\tBit final");
                    }
                }
            }
        }
        else{
            trama=packet.getUByte(16);
            tipo=trama & 0x00000001;
            if(tipo==0){
                System.out.println("\tTrama I");
                trama=trama>>1;
                System.out.println("\tN(S): "+trama);
                trama=packet.getUByte(17);
                pf=trama & 0x00000001;
                trama=trama>>1;
                System.out.println("\tN(R): "+trama);
                if(pf==0){
                    System.out.println("\tSondeo");
                }
                else{
                    System.out.println("\tBit final");
                }
            }
            else{
                trama=trama>>1;
                tipo=trama & 0x00000001;
                if(tipo==0){
                    System.out.println("\tTrama S");
                    trama=trama>>2;
                    codigo=trama & 0x00000001;
                    trama=trama>>1;
                    codigo=((trama & 0x00000001)<<1)+codigo;
                    switch(codigo){
                        case 0: mensaje="Listo para recibir (RR)";
                        break;
                        case 1: mensaje="Rechazo (REJ)";
                        break;
                        case 2: mensaje="Receptor no listo para recibir (RNR)";
                        break;
                        case 3: mensaje="Rechazo selectivo (SREJ)";
                        break;
                    }
                    System.out.println("\tCódigo: "+mensaje);
                    trama=packet.getUByte(17);
                    pf=trama & 0x00000001;
                    trama=trama>>1;
                    System.out.println("\tN(R): "+trama);
                    if(pf==0){
                        System.out.println("\tSondeo");
                    }
                    else{
                        System.out.println("\tBit final");
                    }
                }
                else{
                    System.out.println("\tTrama U");
                    trama=trama>>1;
                    codigo=(trama & 0x00000001)<<4;
                    trama=trama>>1;
                    codigo+=(trama & 0x00000001)<<3;
                    trama=trama>>1;
                    pf=trama & 0x00000001;
                    trama=trama>>1;
                    codigo+=(trama & 0x00000001)<<2;
                    trama=trama>>1;
                    codigo+=(trama & 0x00000001)<<1;
                    trama=trama>>1;
                    codigo+=trama & 0x00000001;
                    switch(codigo){
                        case 1: mensaje="SNRM";
                        break;
                        case 27: mensaje="SNRME";
                        break;
                        case 28: mensaje="SABM";
                        break;
                        case 30: mensaje="SABME";
                        break;
                        case 0: mensaje="UI";
                        break;
                        case 6: mensaje="Reconocimiento sin númerar";
                        break;
                        case 2: mensaje="DISC";
                        break;
                        case 16: mensaje="SIM";
                        break;
                        case 4: mensaje="UP";
                        break;
                        case 25: mensaje="RSET";
                        break;
                        case 29: mensaje="XID";
                        break;
                        case 17: mensaje="FRMR";
                        break;
                        default: mensaje="desconocido";
                        break;
                    }
                    System.out.println("\tComando: "+mensaje);
                    if(pf==0){
                        System.out.println("\tSondeo");
                    }
                    else{
                        System.out.println("\tBit final");
                    }
                }
            }
        }
        System.out.println("-------------------------------------------------");
    }

    public static void analizarProtocoloARP(PcapPacket packet){
        int hardwareType=(packet.getUByte(14)<<8)+packet.getUByte(15),
            opcode=(packet.getUByte(20)<<8)+packet.getUByte(21);
        String mensaje="";
        switch(hardwareType){
            case 1: mensaje="Ethernet (10 Mb)";
            break;
            case 6: mensaje="IEEE 802 Networks";
            break;
            case 7: mensaje="ARCNET";
            break;
            case 15: mensaje="Frame Relay";
            break;
            case 16: mensaje="Asynchronous Transfer Mode (ATM)";
            break;
            case 17: mensaje="HDLC";
            break;
            case 18: mensaje="Fibre Channel";
            break;
            case 19: mensaje="Asynchronous Transfer Mode (ATM)";
            break;
            case 20: mensaje="Serial Line";
            break;
            default: mensaje="Otros";
            break;
        }
        System.out.println("\t\tTipo de hardware: "+mensaje);
        System.out.printf(
                "|-->Tipo de protocolo: %02X %02X\n", packet.getUByte(16),
                packet.getUByte(17)
        );
        System.out.println(
                "|-->Tamaño de la dirección de hardware (MAC): "+packet.getUByte(18)
        );
        System.out.println(
                "|-->Tamaño de la dirección de software (IP): "+packet.getUByte(19)
        );
        switch(opcode){
            case 1: mensaje="ARP Request";
            break;
            case 2: mensaje="ARP Reply";
            break;
            case 3: mensaje="RARP Request";
            break;
            case 4: mensaje="RARP Reply";
            break;
            case 5: mensaje="DRARP Request";
            break;
            case 6: mensaje="DRARP Reply";
            break;
            case 7: mensaje="DRARP Error";
            break;
            case 8: mensaje="InARP Request";
            break;
            case 9: mensaje="InARP reply";
            break;
            default: mensaje="Otros";
            break;
        }
        System.out.println("|-->Op code: "+mensaje);
        System.out.printf(
                "|-->Dirección MAC del remitente: %02X:%02X:%02X:%02X:%02X:%02X\n",
                packet.getUByte(22), packet.getUByte(23), packet.getUByte(24),
                packet.getUByte(25), packet.getUByte(26), packet.getUByte(27)
        );
        System.out.printf(
                "|-->Dirección IP del remitente: %d.%d.%d.%d\n",
                packet.getUByte(28), packet.getUByte(29), packet.getUByte(30),
                packet.getUByte(31)
        );
        System.out.printf(
                "|-->Dirección MAC del destinatario: %02X:%02X:%02X:%02X:%02X:%02X\n",
                packet.getUByte(32), packet.getUByte(33), packet.getUByte(34),
                packet.getUByte(35), packet.getUByte(36), packet.getUByte(37)
        );
        System.out.printf(
                "|-->Dirección IP del destinatario: %d.%d.%d.%d\n",
                packet.getUByte(38), packet.getUByte(39), packet.getUByte(40),
                packet.getUByte(41)
        );
    }

    public static void analizarProtocoloIP(PcapPacket packet){
        Ip4 ip = new Ip4();
        if(packet.hasHeader(ip)){
            //Decodificación de pdu IP
            String mensaje ="";
            int protocolo = ip.type();
            System.out.println("\t\tVersión: "+ip.version());
            System.out.println("\t\tLongitud del encabezado: "+(ip.hlen()*4)+" bytes");
            int servicios = ip.tos();
            int CS = servicios>>>5;
            switch(CS){
                case 7: mensaje="Network Control";
                break;
                case 6: mensaje="Internetwork Control";
                break;
                case 5: mensaje="CRITIC/ECP";
                break;
                case 4: mensaje="Flash Override";
                break;
                case 3: mensaje="Flash";
                break;
                case 2: mensaje="Inmediate";
                break;
                case 1: mensaje="Priority";
                break;
                case 0: mensaje="Routine";
                break;
                default: mensaje="Sin indentificar";
                break;
            }
            System.out.println("\t\tServicios diferenciados: "+mensaje);
            int ECN = servicios & 3;
            switch(ECN){
                case 0: mensaje="Sin capacidad ECN";
                break;
                case 1: mensaje="Capacidad de transporte ECN(0)";
                break;
                case 2: mensaje="Capacidad de transporte ECN(0)";
                break;
                case 3: mensaje="Congestión encontrada";
                break;
            }
            System.out.println("\t\tECN : "+mensaje);
            System.out.println("\t\tLogitud: "+ip.length());
            System.out.printf("\t\tIdentificación: (0x%x) %d\n",ip.id(),ip.id());
            System.out.println("\t\tBandera Don't fragment: "+ip.flags_DF());
            System.out.println("\t\tBandera More fragment: "+ip.flags_MF());
            System.out.println("\t\tDesplazamiento de fragmento: "+ip.offset());
            System.out.println("\t\tTiempo de vida: "+ip.ttl());
            int tipo = ip.type();
            switch(tipo){
                case 1: mensaje="ICMP";
                break;
                default: mensaje="Sin indentificar";
                break;
            }
            System.out.println("\t\tTipo: "+mensaje);
            System.out.printf("\t\tChecksum: 0x%x\n", ip.checksum());
            byte[] source = ip.source();
            System.out.printf("\t\tDirección fuente:  %d.%d.%d.%d\n",
                               source[0] & 0xFF,source[1] & 0xFF,
                               source[2] & 0xFF,source[3] & 0xFF
            );
            byte[] destination = ip.destination();
            System.out.printf("\t\tDirección destino: %d.%d.%d.%d\n",
                               destination[0] & 0xFF, destination[1] & 0xFF,
                               destination[2] & 0xFF, destination[3] & 0xFF
            );
            switch(protocolo){
                case 1://ICMP
                    Icmp icmp = new Icmp();
                    if(packet.hasHeader(icmp)){
                        tipo = icmp.type();
                        int codigo = icmp.code();
                        String mensajeTipo="";
                        mensaje="";
                        switch(tipo){
                            case 0: mensajeTipo="Echo Reply";
                            break;
                            case 3: mensajeTipo="Destination Unreachable";
                                    switch(codigo){
                                        case 0: mensaje="Destination network unreachable";
                                        break;
                                        case 1: mensaje="Destination host unreachable";
                                        break;
                                        case 2: mensaje="Destination protocol unreachable";
                                        break;
                                        case 3: mensaje="Destination port unreachable";
                                        break;
                                        case 4: mensaje="Fragmentacion needed and DF flag set";
                                        break;
                                        case 5: mensaje="Source route failed";
                                        break;
                                    }
                            break;
                            case 5: mensajeTipo="Redirect Menssage";
                                    switch(codigo){
                                        case 0: mensaje="Redirect datagram for the Network";
                                        break;
                                        case 1: mensaje="Redirect datagram for the host";
                                        break;
                                        case 2: mensaje="Redirect datagram for the Type of Service and Network";
                                        break;
                                        case 3: mensaje="Redirect datagram for the Service and Host";
                                        break;
                                    }
                            break;
                            case 8: mensajeTipo="Echo Request";
                            break;
                            case 9: mensajeTipo="Router Advertisement";
                            break;
                            case 10: mensajeTipo="Router Solicitation";
                            break;
                            case 11: mensajeTipo="Time exceeded";
                                     switch(codigo){
                                         case 0: mensaje="Time to live exceeded in transit";
                                         break;
                                         case 1: mensaje="Fragment reassembly time exceeded";
                                         break;
                                     }
                            break;
                            case 12: mensajeTipo="Parameter Problem";
                                     switch(codigo){
                                         case 0: mensaje="Pointer indicates error";
                                         break;
                                         case 1: mensaje="Missing required option";
                                         break;
                                         case 2: mensaje="Bad length";
                                         break;
                                     }
                            break;
                            case 13: mensajeTipo="Timestamp";
                            break;
                            case 14: mensajeTipo="Timestamp Reply";
                            break;
                            default: mensajeTipo="Desconocido";
                            break;
                        }
                        System.out.println("\t\t\t|-->Tipo de trama: ICMP");
                        System.out.println("\t\t\t\tTipo: "+icmp.type()+" "+mensajeTipo);
                        System.out.println("\t\t\t\tCódigo: "+icmp.code()+" "+mensaje);
                        System.out.printf("\t\t\t\tChecksum: 0x%x\n",icmp.checksum());
                    }
                break;
            }
        }
    }

    public static void main(String[] args) {
        Pcap pcap=null;
        try{
            BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
            List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs
            StringBuilder errbuf = new StringBuilder(); // For any error msgs
            System.out.println("[0]-->Realizar captura de paquetes al vuelo");
            System.out.println("[1]-->Cargar traza de captura desde archivo");
            System.out.print("\nElige una de las opciones:");
            int opcion = Integer.parseInt(br.readLine());
            if (opcion==1){

                /////////////////////////lee archivo//////////////////////////
                //String fname = "archivo.pcap";
                String fname = "C:\\Users\\gata2\\Downloads\\ICMP.pcap";
                pcap = Pcap.openOffline(fname, errbuf);
                if (pcap == null) {
                    System.err.printf("Error while opening device for capture: "+ errbuf.toString());
                    return;
                }//if
            }
            else if(opcion==0){
                /***************************************************************************
                * First get a list of devices on this system
                **************************************************************************/
                int r = Pcap.findAllDevs(alldevs, errbuf);
                if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
                    System.err.printf("Can't read list of devices, error is %s", errbuf
                            .toString());
                    return;
                }

                System.out.println("Network devices found:");

                int i = 0;
                for (PcapIf device : alldevs) {
                    String description =
                            (device.getDescription() != null) ? device.getDescription()
                                : "No description available";
                    final byte[] mac = device.getHardwareAddress();
                    String dir_mac = (mac==null)?"No tiene direccion MAC":asString(mac);
                    System.out.printf("#%d: %s [%s] MAC:[%s]\n", i++, device.getName(), description, dir_mac);
                    List<PcapAddr> direcciones = device.getAddresses();
                    for(PcapAddr direccion:direcciones){
                        System.out.println(direccion.getAddr().toString());
                    }//foreach
                }//for

                System.out.print("\nEscribe el número de interfaz a utilizar:");
                int interfaz = Integer.parseInt(br.readLine());
                PcapIf device = alldevs.get(interfaz); // We know we have atleast 1 device
                System.out
                    .printf("\nChoosing '%s' on your behalf:\n",
                        (device.getDescription() != null) ? device.getDescription()
                            : device.getName());

                /***************************************************************************
                * Second we open up the selected device
                **************************************************************************/
                /*"snaplen" is short for 'snapshot length', as it refers to the amount of actual data captured from each packet passing through the specified network interface.
                64*1024 = 65536 bytes; campo len en Ethernet(16 bits) tam máx de trama */

                int snaplen = 64 * 1024;           // Capture all packets, no trucation
                int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
                int timeout = 10 * 1000;           // 10 seconds in millis


                pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

                if (pcap == null) {
                    System.err.printf("Error while opening device for capture: "
                            + errbuf.toString());
                    return;
                }//if

                /********F I L T R O********/
                PcapBpfProgram filter = new PcapBpfProgram();
                String expression =""; // "port 80";
                int optimize = 0; // 1 means true, 0 means false
                int netmask = 0;
                int r2 = pcap.compile(filter, expression, optimize, netmask);
                if (r2 != Pcap.OK) {
                    System.out.println("Filter error: " + pcap.getErr());
                }//if
                pcap.setFilter(filter);
                /****************/
            }//else if

            /***************************************************************************
             * Third we create a packet handler which will receive packets from the
             * libpcap loop.
             **********************************************************************/
            PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {

                public void nextPacket(PcapPacket packet, String user) {

                    /*Imprime fecha del paquete*/
                    System.out.printf("\n\nPaquete recibido el %s caplen=%-4d longitud=%-4d %s\n\n",
                                        new Date(packet.getCaptureHeader().timestampInMillis()),
                                                packet.getCaptureHeader().caplen(),  // Length actually captured
                                                packet.getCaptureHeader().wirelen(), // Original length
                                                user                                 // User supplied object
                    );


                    /******Desencapsulado********/
                    for(int i=0;i<packet.size();i++){
                        System.out.printf("%02X ",packet.getUByte(i));

                        if(i%16==15)
                            System.out.println("");
                    }//if

                    int dsap=0,
                        ig=0,
                        ssap=0,
                        cr=0;
                    int longitud = (packet.getUByte(12)*256)+packet.getUByte(13);
                    System.out.printf("\n\nLongitud: %d (%04X)",longitud,longitud );
                    if(longitud<1500){
                        System.out.println("\n |--->Tipo de trama: IEEE802.3");
                        System.out.printf(" |-->MAC Destino: %02X:%02X:%02X:%02X:%02X:%02X",
                                packet.getUByte(0),packet.getUByte(1),packet.getUByte(2),
                                packet.getUByte(3),packet.getUByte(4),packet.getUByte(5)
                        );
                        System.out.printf("\n |-->MAC Origen: %02X:%02X:%02X:%02X:%02X:%02X",
                                packet.getUByte(6),packet.getUByte(7),packet.getUByte(8),
                                packet.getUByte(9),packet.getUByte(10),packet.getUByte(11)
                        );
                        dsap=packet.getUByte(14);
                        System.out.printf("\n |-->DSAP: %02X\t",dsap);
                        ig=dsap & 0x00000001;
                        System.out.println((ig==0)?"Individual":"Grupal");
                        identificarProtocolo(dsap);
                        ssap=packet.getUByte(15);
                        //System.out.println(packet.getUByte(15)& 0x00000001);
                        //int ssap = packet.getUByte(15)& 0x00000001;
                        //String c_r = (ssap==1)?"Respuesta":(ssap==0)?"Comando":"Otro";
                        System.out.printf(" |-->SSAP: %02X\t",ssap);
                        cr=ssap & 0x00000001;
                        System.out.println((cr==0)?"Comando":"Respuesta");
                        identificarProtocolo(ssap);
                        identificarCampoControl(longitud, packet);
                    }
                    else if(longitud>=1500){
                        System.out.println("\n |-->Tipo de trama: ETHERNET");
                        System.out.printf(" |-->MAC Destino: %02X:%02X:%02X:%02X:%02X:%02X",
                                packet.getUByte(0),packet.getUByte(1),packet.getUByte(2),
                                packet.getUByte(3),packet.getUByte(4),packet.getUByte(5)
                        );
                        System.out.printf("\n |-->MAC Origen: %02X:%02X:%02X:%02X:%02X:%02X",
                                packet.getUByte(6),packet.getUByte(7),packet.getUByte(8),
                                packet.getUByte(9),packet.getUByte(10),packet.getUByte(11)
                        );
                        definirTipoTrama(longitud, packet);
                    }else if(longitud==2054 ){

                                System.out.println("\n|-->Tipo de trama: ARP");

                                System.out.printf("|-->MAC Destino: %02X:%02X:%02X:%02X:%02X:%02X",packet.getUByte(0),packet.getUByte(1),packet.getUByte(2),packet.getUByte(3),packet.getUByte(4),packet.getUByte(5));
                                System.out.printf("\n");
                                System.out.printf("|-->MAC Origen:  %02X:%02X:%02X:%02X:%02X:%02X",packet.getUByte(6),packet.getUByte(7),packet.getUByte(8),packet.getUByte(9),packet.getUByte(10),packet.getUByte(11));
                                System.out.printf("\n");

                                analizarProtocoloARP( packet);

                    }//else


                    //System.out.println("\n\nEncabezado: "+ packet.toHexdump());


                }
            };


            /***************************************************************************
            * Fourth we enter the loop and tell it to capture 10 packets. The loop
            * method does a mapping of pcap.datalink() DLT value to JProtocol ID, which
            * is needed by JScanner. The scanner scans the packet buffer and decodes
            * the headers. The mapping is done automatically, although a variation on
            * the loop method exists that allows the programmer to sepecify exactly
            * which protocol ID to use as the data link type for this pcap interface.
            **************************************************************************/
            pcap.loop(-1, jpacketHandler, " ");

            /***************************************************************************
            * Last thing to do is close the pcap handle
            **************************************************************************/
            pcap.close();
        }
        catch(IOException e){
            e.printStackTrace();
        }
    }
}



//cosas por agregar-------------------------------------------------------
/*
Establecer la cantidad de tramas a mostrar
Exportar a archivo .pcap

*/
