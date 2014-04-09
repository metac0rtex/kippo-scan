kippo-scan
==========

This is a script to scan for Kippo honeypots. It is still extreamly messy and only has basic detection at this point but I am still working on it!


usage: ./kipposcan.py [options]


--== Kippo Scanner ==--


optional arguments:

  -h, --help            show this help message and exit
  
  -f FILE, --file FILE  Specify a list of IPs and Ports in a file. Needs to be
  
                        a single line consisiting of "IP:Port"
                        
  -i IP, --ip IP        IP Address of a suspected Kippo Honeypot
  
  -p PORT, --port PORT  Port of the suspected Kippo Honeypot
  
  -v, --verbose         Turns on verbose mode
  
  -w WRITEFILE, --write WRITEFILE
  
                        Write the sucessful results to file
                        

