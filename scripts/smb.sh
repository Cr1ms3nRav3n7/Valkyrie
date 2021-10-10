#/bin/bash

nmap  --script smb-security-mode.nse -p 445 -iL output/smbhosts.txt | grep "open" > output/smbtargets.txt
