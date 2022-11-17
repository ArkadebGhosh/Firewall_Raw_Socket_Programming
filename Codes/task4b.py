import sys, os
import socket
import fcntl 
import struct
import ctypes
import json
import threading
import binascii

BUFFSIZE = 4096


def icmp_static_rules(soc, src_ip, dst_ip, src_mac, dst_mac, packet):

    ################# STATIC RULES ###############
    if dst_ip == '192.168.100.155':
        print("Dropping packet with src ip" , src_ip, " access denied")
            
    elif dst_mac == '525400df6344' and src_ip == '192.168.100.156':
        
        print("Dropping packet with src mac", src_mac)
    else:
    	soc.sendall(packet[0]) 
    	print("Packet is allowed to pass to VM2 with src ip ", src_ip, "and dst ip number", dst_ip)
    	

def tcp_udp_static_rules(socket, src_ip, dst_ip, src_port, dst_port, src_mac, dst_mac, packet):
    
    ################## STATIC RULES ###############
    if dst_ip == '192.168.100.155' or dst_ip == 80:
        print("Dropping packet with src ip" , src_ip, " access denied")
            
    else:
        socket.sendall(packet[0]) 
        print("Packet is allowed to pass to VM2 with src ip ", src_ip, "and dst port number ", dst_port)

###############################################################################

def firewall(socket1, socket2):
    count = 0
    while(True):
        packet = socket1.recvfrom(BUFFSIZE)
        # Parsing ethernet header
        
        ethernetHeader = packet[0][0:14] # 14 B ether header
        ethernet_hdr = struct.unpack("!6s6sH", ethernetHeader)
        src_mac = binascii.hexlify(ethernet_hdr[0])
        dst_mac = binascii.hexlify(ethernet_hdr[1])
        eth_protocol = socket.ntohs(ethernet_hdr[2])
        print("Source MAC is: ", src_mac)
        print("Dest MAC is: ", dst_mac)
	print("Ethernet Protocol: ", eth_protocol)
        
        
        if eth_protocol == 8: #### IPv4 header ############
             
            # Parsing IP header #####################
    
            ipv4Header = packet[0][14:34] # 20 B IP header
            ipv4_hdr = struct.unpack("!BBHHHBBH4s4s", ipv4Header)
            ipv4_protocol = ipv4_hdr[6]
            src_ip = socket.inet_ntoa(ipv4_hdr[8])
            dest_ip = socket.inet_ntoa(ipv4_hdr[9])
            print("Source IP is: ", src_ip)
            print("Dest IP is: ", dest_ip)
            print("IP protocol is: ", ipv4_protocol)
            # Parsing depending on the type of protocol specified in Ipv4 header protocol field
                
            if ipv4_protocol == 6: # TCP header 20 B
                print("Parsing TCP Header")
                tcpHeader = packet[0][34:54]
                tcp_hdr = struct.unpack("!HH16s", tcpHeader)
                src_port = tcp_hdr[0]
                dst_port = tcp_hdr[1]
                tcp_udp_static_rules(socket2, src_ip, dest_ip, src_port, dst_port, src_mac, dst_mac, packet)
                print("Source port is: ", src_port)
                print("Dest port is: ", dst_port)
                
            elif ipv4_protocol == 17: # UDP header 8 B
                print("Parsing UDP Header")
                udpHeader = packet[0][34:42]
                udp_header = struct.unpack('!HHHH',udpHeader)
                src_port = udp_header[0]
                dst_port = udp_header[1]
                tcp_udp_static_rules(socket1, src_ip, dest_ip, src_port, dst_port, src_mac, dst_mac, packet)
                print("Source port is: ", src_port)
                print("Dest port is: ", dst_port)
                    
            elif ipv4_protocol == 1: # ICMP header 8 B
                print("Parsing ICMP Header")
                icmpHeader = packet[0][34:42]
                icmp_header = struct.unpack('!BBH4s',icmpHeader)
                code = icmp_header[0]
                print("ICMP Code: ", code)
                if count > 1000:
                    print("************ DoS Ping attack detected **************")
                    socket1.close()
                    socket2.close()
                    exit()
                else:
                    icmp_static_rules(socket2, src_ip, dest_ip, src_mac, dst_mac, packet)
                    count = count + 1
                    print("\nCOUNT: ",count)
                    
                    
                    
        elif eth_protocol == 41: ############### IPv6 Header ###################
        
        # Parsing IP header #####################
    
            ipv6Header = packet[0][14:34] # 20 B IP header
            ipv6_hdr = struct.unpack("!4sHBB16s16s", ipv6Header)
            ipv6_protocol = socket1.ntohs(ipv6_hdr[2])
            src_ip = socket1.inet_ntoa(ipv6_hdr[4])
            dest_ip = socket1.inet_ntoa(ipv6_hdr[5])
                    
            # Parsing depending on the type of protocol specified in Ipv6 header protocol field
                
            if ipv6_protocol == 6: # TCP header 20 B
                print("Parsing TCP Header")
                tcpHeader = packet[0][34:54]
                tcp_hdr = struct.unpack("!HH16s", tcpHeader)
                src_port = tcp_hdr[0]
                dst_port = tcp_hdr[1]
                print("Source port is: ", src_port)
                print("Dest port is: ", dst_port)
                tcp_udp_static_rules(socket2, src_ip, dest_ip, src_port, dst_port, src_mac, dst_mac, packet)
                    
            elif ipv6_protocol == 17: # UDP header 8 B
                print("Parsing UDP Header")
                udpHeader = packet[0][34:42]
                udp_header = struct.unpack('!HHHH',udpHeader)
                src_port = udp_header[0]
                dst_port = udp_header[1]
                print("Source port is: ", src_port)
                print("Dest port is: ", dst_port)
                tcp_udp_static_rules(socket2, src_ip, dest_ip, src_port, dst_port, src_mac, dst_mac, packet)
                        
            elif ipv6_protocol == 1: # ICMP header 8 B
                print("Parsing ICMP Header")
                icmpHeader = packet[0][34:42]
                icmp_header = struct.unpack('!BBH4s',icmpHeader)
                code = icmp_header[0]
                print("ICMP Code: ", code)
                icmp_static_rules(socket2, src_ip, dst_port, src_mac, dst_mac, packet)


        

###############################################################################

def main():
    

    
    # Raw socket creation for 2 interfaces
    socket1 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    socket2 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    
    # Bind these raw sockets to 2 interfaces
    socket1.bind(("ens3", 0))  # ens3 attached to Host1
    socket2.bind(("ens8", 0))  # ens8 attached to Host2
    
    
    print("Raw sockets are now bound to interfaces and listening")
    print("Firewall up and running......")
    print("############# Task 4b #############")
    
    
    firewall(socket1, socket2)
    

    
    socket1.close()
    socket2.close()

main()
