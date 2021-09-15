data_folder=our_collected_dataset
./run.sh --input-pcap-file $data_folder/merged_data.pcap \
         --output-pcaps-folder our_collected_dataset_splitted \
         --output-csvs-folder our_collected_dataset_splitted/csvs \
         --attackers-ips-file $data_folder/attackers_ips.txt \
         --victims-ips-file $data_folder/victims_ips.txt \
         --output-data-csv $data_folder/extracted_features.csv \
         --file-max-size 100 \
         --stage 0

