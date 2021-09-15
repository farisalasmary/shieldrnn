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
#

# This script is used to kill ALL created parallel processes to parse the PCAP files.
# It is useful if you need to stop feature extraction processes. 

kill -9 $(ps aux | grep "parse_data_splitted.py" | grep -v "grep" | awk '{ print $2 }')
