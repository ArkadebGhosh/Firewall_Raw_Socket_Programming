import sys
import os
import socket
import fcntl
import struct
import ctypes
import json
import threading
import binascii
from collections import deque
import Queue
import time
from Queue import Queue
BUFFSIZE = 1000000
QSIZE = 100

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
############################################## Validate and check Rules ##################################################


def check_rules(socket, src_ip, dst_ip, src_port, dst_port, src_mac, dst_mac, is_ipv4, is_ipv6, is_tcp, is_udp, is_icmp, packet, rules, stats):

    if (is_ipv4 and 'IPV4' in rules['restricted_protocols']) or (is_ipv6 and 'IPV6' in rules['restricted_protocols']) or\
    (is_tcp and 'TCP' in rules['restricted_protocols']) or (is_udp and 'UDP' in rules['restricted_protocols']) or\
    (is_icmp and 'ICMP' in rules['restricted_protocols']) or \
    match_wildcards(src_ip, rules['restricted_src_ipv4w']) == True or \
    match_wildcards(dst_ip, rules['restricted_dest_ipv4w']) == True or \
    src_ip in rules['restricted_src_ipv4'] or src_ip in rules['restricted_src_ipv6'] or  \
    dst_ip in rules['restricted_dest_ipv4'] or dst_ip in rules['restricted_dest_ipv6'] or \
    str(src_port) in rules['restricted_src_port'] or src_mac in rules['restricted_src_mac'] or \
    str(dst_port) in rules['restricted_dest_port'] or dst_mac in rules['restricted_dest_mac']:

        print("Dropping packet with src ip", src_ip,
              " and dst ip", dst_ip, "## access denied ##")
        stats[2] = stats[2]+1
    else:
        stats[3] = stats[3]+1
        #print('=======length====== ',len(packet[0]))
        #socket.sendall(packet[0])
        print("Packet is allowed to pass having src ip ",
              src_ip, "and dst ip ", dst_ip)

###############################################################################


def read_packets(socket1, q, stats, start_time):
    # q = deque()
    #try:

    while(True):
        current_time = time.time()
        if current_time - start_time > 1:
            start_time = current_time
            f = open('logs/rule_10.txt', 'a')
            print(' '.join(str(v) for v in stats)+'\n')
            f.write(' '.join(str(v) for v in stats)+'\n')
            f.close()
        print('\n======================Buffer size: ',q.qsize(), '=======================', current_time - start_time)
        packet = socket1.recvfrom(BUFFSIZE)
        stats[0] = stats[0]+1
        if q.full() == False:
            q.put(packet)
        else:
            stats[1] = stats[1]+1
            print('Dropping packet due to low buffer space')
    #except Exception as e:
        #print(e)
        #print('Stopping packet reads')
        
        
def firewall(socket2, q, stats):
    while(True):
        # packet = socket1.recvfrom(BUFFSIZE)
        # q = deque()
        #try:
        if q.qsize() == 0:
            continue
        packet = q.get()
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
                True, False, True, False, False, packet, rules, stats)
                print("Source port is: ", src_port)
                print("Dest port is: ", dst_port)
                
            elif ipv4_protocol == 17: # UDP header 8 B
                print("Parsing UDP Header")
                udpHeader = packet[0][34:42]
                udp_header = struct.unpack('!HHHH',udpHeader)
                src_port = udp_header[0]
                dst_port = udp_header[1]
                check_rules(socket2, src_ip, dest_ip, src_port, dst_port, src_mac, dst_mac,
                True, False, False, True, False, packet, rules, stats)
                print("Source port is: ", src_port)
                print("Dest port is: ", dst_port)
                    
            elif ipv4_protocol == 1: # ICMP header 8 B
                print("Parsing ICMP Header")
                icmpHeader = packet[0][34:42]
                icmp_header = struct.unpack('!BBH4s',icmpHeader)
                print("ICMP Code: ", icmp_header[0])
                check_rules(socket2, src_ip, dest_ip, 0, 0, src_mac, dst_mac,
                True, False, False, False, True, packet, rules, stats)
                    
                    
                    
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
                False, True, True, False, False, packet, rules, stats)
                    
            elif ipv6_protocol == 17: # UDP header 8 B
                print("Parsing UDP Header")
                udpHeader = packet[0][34:42]
                udp_header = struct.unpack('!HHHH',udpHeader)
                src_port = udp_header[0]
                dst_port = udp_header[1]
                check_rules(socket2, src_ip, dest_ip, src_port, dst_port, src_mac, dst_mac,
                False, True, False, True, False, packet, rules, stats)
                        
            elif ipv6_protocol == 1: # ICMP header 8 B
                print("Parsing ICMP Header")
                icmpHeader = packet[0][34:42]
                icmp_header = struct.unpack('!BBH4s',icmpHeader)
                print("ICMP Code: ", icmp_header[0])
                check_rules(socket2, src_ip, dest_ip, 0, 0, src_mac, dst_mac,
                False, True, False, False, True, packet, rules, stats)
        #except:
            #continue

        

###############################################################################

def main():
      
    
    # Raw socket creation for 2 interfaces
    socket1 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    socket2 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    
    # Bind these raw sockets to 2 interfaces
    socket1.bind(("ens3", 0))  # ens3 attached to Host1
    socket2.bind(("ens8", 0))  # ens8 attached to Host2
    
    

           
    log = open('logs/rule_10.txt', 'w')
    log.write('')
    log.close()
    print("Raw sockets are now bound to interfaces") 
    print("Firewall up and running......")
    print("############# Task 3 #############")
    start_time = time.time()
    stats = [0, 0, 0, 0] # Read, Dropped due to low buffer, Dropped by firewall, Passed
    f = open('rules.json')
    q = Queue(maxsize = QSIZE)
    thread1 = threading.Thread(target=read_packets, args=(socket1, q, stats, start_time))
    thread2 = threading.Thread(target=firewall, args=(socket2, q, stats))
    thread1.start()
    thread2.start()
    thread1.join()
    thread2.join()

    log = open('logs/rule_10.txt', 'a')
    log.write(' '.join(stats))
    log.close()
    socket1.close()
    socket2.close()
    

    
    

main()
