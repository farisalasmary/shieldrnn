#!/bin/bash

#    @author
#          ______         _                  _
#         |  ____|       (_)           /\   | |
#         | |__ __ _ _ __ _ ___       /  \  | | __ _ ___ _ __ ___   __ _ _ __ _   _
#         |  __/ _` | '__| / __|     / /\ \ | |/ _` / __| '_ ` _ \ / _` | '__| | | |
#         | | | (_| | |  | \__ \    / ____ \| | (_| \__ \ | | | | | (_| | |  | |_| |
#         |_|  \__,_|_|  |_|___/   /_/    \_\_|\__,_|___/_| |_| |_|\__,_|_|   \__, |
#                                                                              __/ |
#                                                                             |___/
#            Email: farisalasmary@gmail.com
#            Date:  Jul 29, 2021

# This scripts train the models on CIC-IDS2017-Wednesday PCAP traffic trace.
# We assume that the PCAP file is already in the folder specified by the
# variable "data_folder" below. Also, the attackers IPs and victims IPs should be
# provided to the script

data_folder=CIC-IDS-2017/wedday
./run.sh --input-pcap-file $data_folder/Wednesday-WorkingHours.pcap \
         --output-pcaps-folder wed_pcap_splitted \
         --output-csvs-folder wed_pcap_splitted/csvs \
         --attackers-ips-file $data_folder/attackers_ips.txt \
         --victims-ips-file $data_folder/victims_ips.txt \
         --output-data-csv $data_folder/extracted_features.csv \
         --file-max-size 500 \
         --stage 0

