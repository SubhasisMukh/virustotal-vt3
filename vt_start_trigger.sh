#!/bin/bash

TARGET=/home/subhasis/Desktop/Honeypots/deployed_in_cloud/blr_dionaea/binaries
#PROCESSED=send_to/

python3 vt_upload_folder.py
inotifywait -m -e create -e moved_to --format "%f" $TARGET \
        | while read FILENAME
                do
                	sleep 2s
                        python3 vt_upload_cmd_line.py
                done

