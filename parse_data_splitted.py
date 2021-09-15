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
            Date:  Jul 29, 2021
"""

# This script is used to extract features from PCAP files.

# capinfos -M -c CIC-IDS-2017_SPLITTED/6/wed.pcap6 
# tcpdump -r CIC-IDS-2017/Wednesday-WorkingHours.pcap -w CIC-IDS-2017_SPLITTED/wed.pcap -C 1000

import utils
import pyshark
import csv
import pandas as pd
import argparse
import time


def encode_protocols(data):
    data = data.copy()
    data['is_TCP'] = 0
    data['is_UDP'] = 0
    data['is_SSL'] = 0
    data['is_ICMP'] = 0
    data['is_DNS'] = 0
    data['is_OTHER'] = 0
    data.loc[(data['protocol'] == 'TCP'),'is_TCP'] = 1
    data.loc[(data['protocol'] == 'DATA') | (data['protocol'] == 'UDP'),'is_UDP'] = 1
    data.loc[(data['protocol'] == 'SSL'),'is_SSL'] = 1
    data.loc[((data['protocol'] == 'ICMP') | (data['protocol'] == 'ICMPV6')),'is_ICMP'] = 1
    data.loc[(data['protocol'] == 'DNS'),'is_DNS'] = 1
    data.loc[   ~(
                        (data['protocol'] == 'TCP') |
                        (data['protocol'] == 'UDP') |
                        (data['protocol'] == 'DATA') |
                        (data['protocol'] == 'ICMP') |
                        (data['protocol'] == 'ICMPV6') |
                        (data['protocol'] == 'ICMP') |
                        (data['protocol'] == 'SSL') |
                        (data['protocol'] == 'DNS')
                    )
                ,'is_OTHER'] = 1
    return data


def extract_features(packet, attackers_ips, victims_ips, previous_packet=None):
    packet_features = {
                'frame.encap_type': '0',
                'frame.len': '0',
                'frame.protocols': '0',
                'ip.hdr_len': '0',
                'ip.len': '0',
                'ip.flags.rb': '0',
                'ip.flags.df': '0',
                'ip.flags.mf': '0',
                'ip.frag_offset': '0',
                'ip.ttl': '0',
                'ip.proto': '0',
                'ip.src': '0',
                'ip.dst': '0',
                'tcp.srcport': '0',
                'tcp.dstport': '0',
                'tcp.len': '0',
                'tcp.ack': '0',
                'tcp.flags.res': '0',
                'tcp.flags.ns': '0',
                'tcp.flags.cwr': '0',
                'tcp.flags.ecn': '0',
                'tcp.flags.urg': '0',
                'tcp.flags.ack': '0',
                'tcp.flags.push': '0',
                'tcp.flags.reset': '0',
                'tcp.flags.syn': '0',
                'tcp.flags.fin': '0',
                'tcp.window_size': '0',
                'tcp.time_delta': '0',
                'flow_speed': '0',
                'protocol': 'UNKNOWN'
            }
    
    for field_name in packet_features:
        if field_name.startswith('frame.'):  # extract frame info
            packet_features[field_name] = packet.frame_info._all_fields[field_name]
        
        elif field_name.startswith('ip.'):   # extract IP info
            if hasattr(packet, 'ip'):
                packet_features[field_name] = packet.ip._all_fields[field_name]
        
        elif field_name.startswith('tcp.'):  # extract TCP info
            if hasattr(packet, 'tcp'):
                packet_features[field_name] = packet.tcp._all_fields[field_name]
    
    # the following UDP code will be executed if the packet is NOT a TCP packet
    if hasattr(packet, 'udp'):
        # add UDP info as if they were for TCP
        packet_features['tcp.srcport'] = str(packet.udp._all_fields['udp.srcport'])
        packet_features['tcp.dstport'] = str(packet.udp._all_fields['udp.dstport'])
        packet_features['tcp.len'] = str(packet.udp._all_fields['udp.length'])
    
    flow_speed = 0   # time difference between two packets
    if previous_packet is not None:
        packet_features['flow_speed'] = int(packet.sniff_time.timestamp() * 1000 * 1000) - int(previous_packet.sniff_time.timestamp() * 1000 * 1000) #28
    
    packet_features['protocol'] = str(packet.highest_layer) # protocol
    
    label = 'attack' if (packet_features['ip.src'] in attackers_ips and packet_features['ip.dst'] in victims_ips) else 'normal'
    
    packet_features['label'] = label
    
    return packet_features


def parse_pcap(input_pcap_file, output_csv_file, attackers_ips, victims_ips, max_num_packets=2500000, verbose=1000, max_num_packets_in_buffer=10000):
    headings = [
                'frame.encap_type',
                'frame.len',
                'frame.protocols',
                'ip.hdr_len',
                'ip.len',
                'ip.flags.rb',
                'ip.flags.df',
                'ip.flags.mf',
                'ip.frag_offset',
                'ip.ttl',
                'ip.proto',
                'ip.src',
                'ip.dst',
                'tcp.srcport',
                'tcp.dstport',
                'tcp.len',
                'tcp.ack',
                'tcp.flags.res',
                'tcp.flags.ns',
                'tcp.flags.cwr',
                'tcp.flags.ecn',
                'tcp.flags.urg',
                'tcp.flags.ack',
                'tcp.flags.push',
                'tcp.flags.reset',
                'tcp.flags.syn',
                'tcp.flags.fin',
                'tcp.window_size',
                'tcp.time_delta',
                'flow_speed',
                'protocol',
                'label'
            ]
    clean_features_with_label = [
                 'frame.len',
                 'ip.hdr_len',
                 'ip.len',
                 'ip.ttl',
                 'tcp.srcport',
                 'tcp.dstport',
                 'tcp.len',
                 'tcp.window_size',
                 'tcp.time_delta',
                 'flow_speed',
                 'tcp.ack',
                 'ip.flags.rb',
                 'ip.flags.df',
                 'ip.flags.mf',
                 'ip.frag_offset',
                 'tcp.flags.res',
                 'tcp.flags.ns',
                 'tcp.flags.cwr',
                 'tcp.flags.ecn',
                 'tcp.flags.urg',
                 'tcp.flags.ack',
                 'tcp.flags.push',
                 'tcp.flags.reset',
                 'tcp.flags.syn',
                 'tcp.flags.fin',     
                 'is_TCP',
                 'is_UDP',
                 'is_ICMP',
                 'is_DNS',
                 'is_SSL',
                 'is_OTHER',
                 'label'
                ]
    
    packet_list = []
    cap = pyshark.FileCapture(input_pcap_file, keep_packets=False) #, use_json=True)
    #cap.set_debug() 
    
    data = pd.DataFrame.from_records(packet_list, columns=headings)
    data = encode_protocols(data)
    # data = data.drop(['ip.src', 'ip.dst','frame.protocols'], axis=1)
    data = data[clean_features_with_label]
    data.to_csv(output_csv_file, index=False) # write empty file initially
    
    previous_packet = None
    for i, packet in enumerate(cap):
        packet_features = extract_features(packet, attackers_ips, victims_ips, previous_packet)
        packet_list.append(packet_features)
        previous_packet = packet
        
        if verbose != 0: # skip printing if it is 0
            if (i+1) % verbose == 0:
                print(f'File: {input_pcap_file}, Packet #{i+1}')
        
        if max_num_packets != 0: # extract ALL packets from PCAP if max_num_packets is set to 0
            if (i+1) % max_num_packets == 0:
                break
        
        if len(packet_list) >= max_num_packets_in_buffer:
            data = pd.DataFrame.from_records(packet_list)
            data = encode_protocols(data)
            # data = data.drop(['ip.src', 'ip.dst','frame.protocols'], axis=1)
            data = data[clean_features_with_label]
            data.to_csv(output_csv_file, mode='a', header=False, index=False)
            packet_list = [] # IMPORTANT: this list should be empty once it is written on disk

    if len(packet_list) > 0:
        data = pd.DataFrame.from_records(packet_list)
        data = encode_protocols(data)
        # data = data.drop(['ip.src', 'ip.dst','frame.protocols'], axis=1)
        data = data[clean_features_with_label]
        data.to_csv(output_csv_file, mode='a', header=False, index=False)
    

def main():
    def check_positive(value):
        ivalue = int(value)
        if ivalue < 0:
            raise argparse.ArgumentTypeError("%s is an invalid positive int value" % value)
        return ivalue
    
    parser = argparse.ArgumentParser()
    parser.add_argument('--input-folder', help='Input folder that contains PCAP files', required=True)
    parser.add_argument('--output-folder', help='Output folder that will have the extracted packets features in CSV format', required=True)
    parser.add_argument('--attackers-ips-file', help='a text file that contains the IPs of the attackers to be used for packets labelling', required=True)
    parser.add_argument('--victims-ips-file', help='a text file that contains the IPs of the victims to be used for packets labelling', required=True)
    parser.add_argument('--max-num-pkts', help='Maximum number of extracted packets per file. Default: 0 means ALL',
                                          default=0, type=check_positive)
    parser.add_argument('--max-num-pkts-in-buffer', help='Maximum number of extracted packets that are kept in buffer '
                                                         'before appending them to the CSV file. Default: 1000',
                                                    default=1000, type=check_positive)
    parser.add_argument('--verbose', help='print number of processed packets so far. number should be positive integer > 0. '
                                          'if 0 is provided, no message will be shown. Default: 1000 means print after processing each 1000 packet',
                                     default=1000, type=check_positive)
    args = parser.parse_args()
    
    input_folder = args.input_folder
    output_folder = args.output_folder

    output_folder = output_folder.rstrip('/')
    utils.makedirectory(output_folder)

    pcap_files = utils.get_files(input_folder, '*.pcap*')
    completed_files = []
    for f in utils.get_files(output_folder, "*.csv"):
         completed_files.append(utils.extract_filename(f))
    
    completed_files = set(completed_files) # convert list to set for fast search
    
    overall_start_time = time.time()
    for i, input_pcap_file in enumerate(pcap_files):
        pcap_filename = utils.extract_filename(input_pcap_file)
        if pcap_filename in completed_files:
            print(f'Skip Processing file: {input_pcap_file} since it is already processed!')
            continue
        
        print(f'Processing file: {input_pcap_file}')
        output_csv_file = f'{output_folder}/{pcap_filename}.csv'
        
        attackers_ips = []
        with open(args.attackers_ips_file) as f1:
            attackers_ips = [ip.strip() for ip in f1.readlines()]
        
        victims_ips = []
        with open(args.victims_ips_file) as f1:
            victims_ips = [ip.strip() for ip in f1.readlines()]
        
        # for faster searching, convert the lists of ips into sets
        attackers_ips = set(attackers_ips)
        victims_ips = set(victims_ips)
        
        start_time = time.time()
        parse_pcap(input_pcap_file, output_csv_file, attackers_ips, victims_ips,
                    max_num_packets=args.max_num_pkts, verbose=args.verbose,
                    max_num_packets_in_buffer=args.max_num_pkts_in_buffer)
        end_time = time.time()
        
        completed_files.add(pcap_filename)
        print(f'# of Completed Files: {i+1}/{len(pcap_files)}, Total time: {end_time - start_time}')

    overall_end_time = time.time()
    print(f'Total time of processing {len(pcap_files)} PCAP files is: {overall_end_time - overall_start_time}')

if __name__ == '__main__':
    main()





