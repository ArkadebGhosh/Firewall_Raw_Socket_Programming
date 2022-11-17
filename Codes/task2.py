import sys, os
import socket
import fcntl 
import struct
import ctypes
import json
import threading
import binascii

BUFFSIZE = 2048

def match_wildcard(ip, wc):
    a1 = ip.split('.')
    a2 = wc.split('.')
    for i in range(len(a1), -1):
        if a2[i] == '*':
            continue
        elif a2[i] != a1[i]:
            return False
    return True
    
def match_wildcards(ip, wcs):
    for wc in wcs:
        if match_wildcard(ip, wc) == True:
            return True
    return False
############################################## TASK 2 Validate and check Rules ##################################################
def check_rules(socket, src_ip, dst_ip, src_port, dst_port, src_mac, dst_mac, is_ipv4, is_ipv6, is_tcp, is_udp, is_icmp, packet, rules):
    
    if (is_ipv4 and 'IPV4' in rules['restricted_protocols']) or (is_ipv6 and 'IPV6' in rules['restricted_protocols']) or\
    (is_tcp and 'TCP' in rules['restricted_protocols']) or (is_udp and 'UDP' in rules['restricted_protocols']) or\
    (is_icmp and 'ICMP' in rules['restricted_protocols']) or \
    match_wildcards(src_ip, rules['restricted_src_ipv4w']) == True or \
    match_wildcards(dst_ip, rules['restricted_dest_ipv4w']) == True or \
    src_ip in rules['restricted_src_ipv4'] or src_ip in rules['restricted_src_ipv6'] or  \
    dst_ip in rules['restricted_dest_ipv4'] or dst_ip in rules['restricted_dest_ipv6'] or \
    str(src_port) in rules['restricted_src_port'] or src_mac in rules['restricted_src_mac'] or \
    str(dst_port) in rules['restricted_dest_port'] or dst_mac in rules['restricted_dest_mac']:
        
        print("Dropping packet with src ip" , src_ip, " and dst ip", dst_ip, "## access denied ##")
            
    else:
        socket.sendall(packet[0]) 
        print("Packet is allowed to pass having src ip ", src_ip, "and dst ip ", dst_ip)

###############################################################################

def firewall(socket1, socket2):
    while(True):
        packet = socket1.recvfrom(BUFFSIZE)
        f = open('rules.json')
        rules = json.load(f)
        f.close()
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
                check_rules(socket2, src_ip, dest_ip, src_port, dst_port, src_mac, dst_mac,
                True, False, True, False, False, packet, rules)
                print("Source port is: ", src_port)
                print("Dest port is: ", dst_port)
                
            elif ipv4_protocol == 17: # UDP header 8 B
                print("Parsing UDP Header")
                udpHeader = packet[0][34:42]
                udp_header = struct.unpack('!HHHH',udpHeader)
                src_port = udp_header[0]
                dst_port = udp_header[1]
                check_rules(socket2, src_ip, dest_ip, src_port, dst_port, src_mac, dst_mac,
                True, False, False, True, False, packet, rules)
                print("Source port is: ", src_port)
                print("Dest port is: ", dst_port)
                    
            elif ipv4_protocol == 1: # ICMP header 8 B
                print("Parsing ICMP Header")
                icmpHeader = packet[0][34:42]
                icmp_header = struct.unpack('!BBH4s',icmpHeader)
		print("ICMP Code: ", icmp_header[0])
                check_rules(socket2, src_ip, dest_ip, 0, 0, src_mac, dst_mac,
                True, False, False, False, True, packet, rules)
                    
                    
                    
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
                check_rules(socket2, src_ip, dest_ip, src_port, dst_port, src_mac, dst_mac,
                False, True, True, False, False, packet, rules)
                    
            elif ipv6_protocol == 17: # UDP header 8 B
                print("Parsing UDP Header")
                udpHeader = packet[0][34:42]
                udp_header = struct.unpack('!HHHH',udpHeader)
                src_port = udp_header[0]
                dst_port = udp_header[1]
                check_rules(socket2, src_ip, dest_ip, src_port, dst_port, src_mac, dst_mac,
                False, True, False, True, False, packet, rules)
                        
            elif ipv6_protocol == 1: # ICMP header 8 B
                print("Parsing ICMP Header")
                icmpHeader = packet[0][34:42]
                icmp_header = struct.unpack('!BBH4s',icmpHeader)
		print("ICMP Code: ", icmp_header[0])
                check_rules(socket2, src_ip, dest_ip, 0, 0, src_mac, dst_mac,
                False, True, False, False, True, packet, rules)


        

###############################################################################

def main():
    

    
    # Raw socket creation for 2 interfaces
    socket1 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    socket2 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    
    # Bind these raw sockets to 2 interfaces
    socket1.bind(("ens3", 0))  # ens3 attached to Host1
    socket2.bind(("ens8", 0))  # ens8 attached to Host2
    
    
           
    
    print("Raw sockets are now bound to interfaces") 
    print("Firewall up and running......")
    print("############# Task 2 #############")
    

    
    f = open('rules.json')

    firewall(socket1, socket2)

    socket1.close()
    socket2.close()
    print('\n...............Exiting Firewall...............\n')
    

    
    socket1.close()
    socket2.close()

main()
