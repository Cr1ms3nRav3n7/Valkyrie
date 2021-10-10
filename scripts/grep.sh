#!/bin/bash

cat output/rdns.txt | grep ')' | cut -d ' ' -f 6 | grep '1' | sed 's/)//g' | sed 's/(//g' | uniq > output/alive.txt


