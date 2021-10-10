#!/bin/bash


cat output/subnets.txt | while read line
	 do
 
	for i in {1..254}
		do (ping -c 1 $line.$i | grep "bytes from" | cut -d ' '  -f 4 | sed 's/://g'&) >> output/hosts.txt 
		done 
	done
