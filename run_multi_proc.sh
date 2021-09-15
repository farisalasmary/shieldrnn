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

# This script is used to extract features from large PCAP files. It splits the file into multiple files
# with the specified max file size and extract features for each file in parallel.
#
# NOTE: this took me more than 2 hours to complete

# arguements
input_pcap_file=pcaps/large_file.pcap
output_pcaps_folder=pcaps_multi_process/
output_csvs_folder=$output_pcaps_folder/csv

attackers_ips_file=pcaps/attackers_ips.txt
victims_ips_file=pcaps/victims_ips.txt

# size in megabytes. e.g. 1 means 1 MB and 1000 means 1000 MB, i.e., 1 GB
file_max_size=1000

. ./parse_options.sh # accept options

echo "input_pcap_file: $input_pcap_file"
echo "output_pcaps_folder: $output_pcaps_folder"
echo "output_csvs_folder: $output_csvs_folder"
echo "attackers_ips_file: $attackers_ips_file"
echo "victims_ips_file: $victims_ips_file"
echo "file_max_size: $file_max_size"


mkdir -p $output_pcaps_folder
#mkdir -p $output_csvs_folder

echo "Splitting file $input_pcap_file into multiple files and store them in $output_pcaps_folder"
tcpdump -r $input_pcap_file -w $output_pcaps_folder/file_chunk -C $file_max_size

echo "Calculating the number of packets of the splitted files and the number of packets in the input file..."
splitted_files_sizes_sum=$(capinfos $output_pcaps_folder/* -M -c | grep "Number of packets:" | awk '{sum+=$NF} END {print sum}')
input_file_size=$(capinfos $input_pcap_file -M -c | grep "Number of packets:" | awk '{ print $NF }')

if [ $splitted_files_sizes_sum -eq $input_file_size ]; then
    echo "Info: The number of packets in splitted files and the input file is the same: $input_file_size..."
else
    echo 'Error: The number of packets in splitted files and the input file is DIFFERENT!!!'
    echo "splitted_files_sizes_sum = $splitted_files_sizes_sum and input_file_size = $input_file_size"
    exit 1;
fi

splitted_files=$(ls $output_pcaps_folder)
for file in $splitted_files
do 
    echo $file; 
    mv $output_pcaps_folder/$file $output_pcaps_folder/$file.pcap
done

num_of_files=$(ls $output_pcaps_folder | wc -l)
num_of_files=$[num_of_files - 1] # subtract one since the first file has a special name that does not include part number

mkdir -p $output_pcaps_folder/0
mv $output_pcaps_folder/file_chunk.pcap $output_pcaps_folder/0/file_chunk.pcap


for i in $(seq 1 $num_of_files)
do
    echo "Moving file: $output_pcaps_folder/file_chunk$i.pcap to $output_pcaps_folder/$i/file_chunk.pcap"
    mkdir -p $output_pcaps_folder/$i
    mv $output_pcaps_folder/file_chunk$i.pcap $output_pcaps_folder/$i/file_chunk.pcap
done

echo "Running a process for each file chunk..."
for i in $(seq 0 $num_of_files)
do
    echo "Running process #$i"
    python parse_data_splitted.py --input-folder $output_pcaps_folder/$i \
                                  --output-folder $output_csvs_folder/$i \
                                  --max-num-pkts-in-buffer 1000 \
                                  --attackers-ips-file $attackers_ips_file \
                                  --victims-ips-file $victims_ips_file &
done
echo "All processes are running!! just waiting for all processes to complete!"
wait

echo "DONE!!!!!!"




