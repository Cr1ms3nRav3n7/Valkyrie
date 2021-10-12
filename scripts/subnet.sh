#!/bin/bash

cat output/hosts.txt | cut -d '.' -f 1,2,3 | uniq > output/subnets.txt

rm output/hosts.txt
