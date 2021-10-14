#!/usr/bin/env python3
#rDNS sweeps and initial enumeration for internal penetration tests
#author: Cr1ms3nRav3n
#version: 1.0

import sys
import subprocess
import nmap
import argparse
from termcolor import colored
from subprocess import call
from os.path import exists

#define nmap
nm = nmap.PortScanner()
#define nmapa
nma = nmap.PortScannerAsync()

#define arguments
parser = argparse.ArgumentParser(description='Tool to enumerate private networks.')
parser.add_argument("--rdns", help="Perform RDNS sweeps of private subnets", action="store_true")
parser.add_argument("--nmap", help="Perform nmap scans of enumerated subnet. This will not work if RDNS sweeps have not been performed.", action="store_true")
args = parser.parse_args()

#print banner
b= open ('valk.txt', 'r')
print(colored(''.join([line for line in b]),'blue')) 


if args.rdns:
	
	#Check for exclusions.txt.	
	file = 'exclusions.txt'
	file_exists = exists(file)
	if file_exists == True:
	

		print (colored('Starting rDNS sweeps, this could take a while...','blue'))
		
		args = "-sL -R --excludefile {}".format(file)
		
		#Perform RDNS sweeps on private subnets with nmap and write to file output/rdns.txt
		nm.scan(hosts='10.0.0.0/8 172.16.0.0/12 192.168.0.0/16', arguments=args)
		f = open('output/hosts.txt', "w")
		g = open('output/rdns.txt', 'w')
		for host in nm.all_hosts():
			hostname = nm[host].hostname()
			if hostname != '':
				print (host, file=f)
				print (host, nm[host].hostname(), file=g)
		f.close()
		g.close()

		print()
		print(colored('rDNS sweeps done!', 'blue'))

		print()
		print(colored('Creating list of subnets to sweep...', 'blue'))
		
		#Calls bash script to grep the rdns.txt file and ouput a list of subnets with live hosts
		call("scripts/subnet.sh")

		print()
		print(colored('Sweeping enumerated subnets...', 'blue'))

		#ICMP ping sweep of enumerated subnets
		sweep = open('output/subnets.txt', 'r')
		lines = sweep.readlines()
		arg2 = "-sn -n -PE --excludefile {}".format(file)


		for line in lines:
			output = 'output/'+line.strip()+'.txt'
			f = open(output, 'w')
			subnet=line.strip()+'.0/24'
			nma.scan(hosts=subnet, arguments=arg2)
			while nma.still_scanning():
				print("Scanning ", subnet)
			for host in nma.all_hosts():
				status = nma[host].state()
				if status == 'up':
					print(host, file=f)
				
			

		print()
		print(colored('Initial enumeration done, check output for files to use for further nmap scans!', 'blue'))
	else:
		print()
		print(colored("exclusions.txt does not exist. Please create the file and try again.", "red"))



