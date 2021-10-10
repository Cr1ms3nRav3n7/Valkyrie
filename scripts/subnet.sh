#!/bin/bash

cat output/alive.txt | cut -d '.' -f 1,2,3 | uniq > output/subnets.txt

rm output/alive.txt
