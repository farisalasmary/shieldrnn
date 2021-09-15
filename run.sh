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

# This is the main script that is used to run the whole experiment

# Here are the training recipe arguements. Change them to fit your data
stage=0
input_pcap_file=test_pcaps_large/large_file.pcap
output_pcaps_folder=test_pcaps_multi_process/
output_csvs_folder=$output_pcaps_folder/csv

attackers_ips_file=test_pcaps_large/attackers_ips.txt
victims_ips_file=test_pcaps_large/victims_ips.txt
output_data_csv=test_pcaps_large/extracted_features.csv

# size in megabytes. e.g. 1 means 1 MB and 1000 means 1000 MB, i.e., 1 GB
file_max_size=500

. ./parse_options.sh # accept options


if [ $stage -le 1 ]; then
    echo "#############################################################"
    echo "Stage 1: Splitting the large PCAP file and extracting features...."
    echo "#############################################################"
    ./run_multi_proc.sh --input-pcap-file $input_pcap_file \
                        --output-pcaps-folder $output_pcaps_folder \
                        --output-csvs-folder $output_csvs_folder \
                        --attackers-ips-file $attackers_ips_file \
                        --victims-ips-file $victims_ips_file \
                        --file-max-size $file_max_size \
                        || exit 1;
fi

if [ $stage -le 2 ]; then
    echo "#############################################################"
    echo "Stage 2: Combine prepared CSV files into one file...."
    echo "#############################################################"
    ./combine_csv_files.sh --input-csvs-folder $output_csvs_folder \
                           --output-combined-file $output_data_csv  \
                           || exit 1;

fi

if [ $stage -le 3 ]; then
    echo "#############################################################"
    echo "Stage 3: Training...."
    echo "#############################################################"
    python -i train_shieldrnn.py --dataset-csv-file $output_data_csv
fi


