#!/usr/bin/env python3
#rDNS sweeps and initial enumeration for internal penetration tests
#author: Cr1ms3nRav3n
#version: 1.0

import sys
import subprocess
import nmap
from termcolor import colored
from subprocess import call
from os.path import exists

#define nmap
nmap = nmap.PortScanner()

#print banner
b= open ('valk.txt', 'r')
print(colored(''.join([line for line in b]),'blue')) 

#Check for exclusions
answer = input('Are there any exclusions for this? y/n ')

if answer == 'y':
	
	#Get file for exclusions	
	file = input('Enter the path to the exclusions file: ')
	file_exists = exists(file)
	if file_exists == True:
	

		print (colored('Starting rDNS sweeps, this could take a while...','blue'))
		
		args = "-sL -R --excludefile {}".format(file)
		
		nmap.scan(hosts='192.168.2.0/24', arguments=args)
		f = open('output/hosts.txt', "w")
		g = open('output/rdns.txt', 'w')
		for host in nmap.all_hosts():
			hostname = nmap[host].hostname()
			if hostname != '':
				print (host, file=f)
				print (host, nmap[host].hostname(), file=g)
		f.close()
		g.close()

		print()
		print(colored('rDNS sweeps done!', 'blue'))

		print()
		print(colored('Creating list of subnets to sweep...', 'blue'))

		call("scripts/subnet.sh")

		print()
		print(colored('Sweeping enumerated subnets...', 'blue'))

		sweep = open('output/subnets.txt', 'r')
		lines = sweep.readlines()
		arg2 = "-sn -n -PE --excludefile {}".format(file)


		for line in lines:
			output = 'output/'+line.strip()+'.txt'
			f = open(output, 'w')
			subnet=line.strip()+'.0/24'
			nmap.scan(hosts=subnet, arguments=arg2)
			for host in nmap.all_hosts():
				status = nmap[host].state()
				if status == 'up':
					print(host, file=f)
				
			

		print()
		print(colored('Initial enumeration done, check output for files to use for further nmap scans!', 'blue'))
	else:
		text = "{} does not exist, check your path.".format(file)
		print()
		print(colored(text, 'red'))

if answer == 'n':
	print('No exclusions, continuing...')
	print()
	print (colored('Starting rDNS sweeps, this could take a while...','blue'))

	nmap.scan(hosts='192.168.2.0/24', arguments='-sL -R')
	f = open('output/hosts.txt', "w")
	g = open('output/rdns.txt', 'w')
	for host in nmap.all_hosts():
		hostname = nmap[host].hostname()
		if hostname != '':
			print (host, file=f)
			print (host, nmap[host].hostname(), file=g)
	f.close()
	g.close()

	print()
	print(colored('rDNS sweeps done!', 'blue'))

	print()
	print(colored('Creating list of subnets to sweep...', 'blue'))

	call("scripts/subnet.sh")

	print()
	print(colored('Sweeping enumerated subnets...', 'blue'))

	sweep = open('output/subnets.txt', 'r')
	lines = sweep.readlines()


	for line in lines:
		file = 'output/'+line.strip()+'.txt'
		f = open(file, 'w')
		subnet=line.strip()+'.0/24'
		nmap.scan(hosts=subnet, arguments='-sn -n -PE')
		for host in nmap.all_hosts():
			status = nmap[host].state()
			if status == 'up':
				print(host, file=f)
elif answer != 'y' or answer != 'n' and file == '':
	print()
	print(colored("Invalid argument, please use 'y' or 'n'", 'red'))



