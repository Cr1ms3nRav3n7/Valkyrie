#!/bin/bash

cat output/nmaprnd1.txt | grep -w "Discovered open port 80" | cut -d ' ' -f 6 > output/httphosts.txt

cat output/nmaprnd1.txt | grep -w "Discovered open port 443" | cut -d ' ' -f 6 > output/httpshosts.txt

cat output/nmaprnd1.txt | grep -w "Discovered open port 445" | cut -d ' ' -f 6 > output/smbhosts.txt
