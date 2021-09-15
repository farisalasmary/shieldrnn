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
#            Date:  July 29, 2021

# This script combines the extracted features from ALL parallel processes into a single CSV file

input_csvs_folder=
output_combined_file=

. ./parse_options.sh # accept options

if [[ -z "$input_csvs_folder" ]]; then
    echo "No input csv folder was provided!";
    echo "Usage: $0 --input-csvs-folder INPUT_CSV_FOLDER --output-combined-file OUTPUT_COMBINED_CSV_FILE";
    echo "E.g. $0 --input-csvs-folder csv_folder/ --output-combined-file merged.csv";
    exit 1;
fi

if [[ -z "$output_combined_file" ]]; then
    echo "No output csv file was provided!";
    echo "Usage: $0 --input-csvs-folder INPUT_CSV_FOLDER --output-combined-file OUTPUT_COMBINED_CSV_FILE";
    echo "E.g. $0 --input-csvs-folder csv_folder/ --output-combined-file merged.csv";
    exit 1;
fi

echo "Input Folder: $input_csvs_folder"
echo "Output combined file: $output_combined_file"

num_of_files=$(ls $input_csvs_folder | wc -l)
num_of_files=$[num_of_files - 1] # subtract one since our index starts from 0

cat $input_csvs_folder/0/file_chunk.csv > $input_csvs_folder/merged.csv || exit 1;
for i in $(seq 1 $num_of_files)
    do
    filename=$input_csvs_folder/$i/file_chunk.csv && \
    len=$(wc -l $filename | awk '{print $1}') && len=$[len-1] && \
    tail -n $len $filename >> $input_csvs_folder/merged.csv || exit 1;
done

mv $input_csvs_folder/merged.csv $output_combined_file


