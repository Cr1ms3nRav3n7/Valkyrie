#!/bin/bash
#Script to easily output a list of ip's with a specific open port from a list of nmap scans

if [ "$1" != ' ' ] && [ "$2" != '' ] && [ "$3" != '' ]
then
  FILES="$3*"
  for f in $FILES
    do
      cat $f | grep "Discovered open port $1" | cut -d ' ' -f 6 >> $2.txt
    done
else
  echo ''
  echo "Usage: ./hostbyport.sh port servicename pathtonmapfiles"
  echo ''
  echo"Example: ./hostbyport.sh 21 ftp '/recon/nmapscans/'"
