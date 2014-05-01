#!/usr/bin/env python


#This must be one of the first imports or else we get threading error on completion
from gevent import monkey
monkey.patch_all()

from gevent.pool import Pool
from gevent import joinall

import argparse
import socket
import pexpect
import sys
import time
import re
import os

def banner():
    print "--== Kippo Scanner ==--"
    print "    By: Metacortex"
    print "        DC801"

def args():
    parser = argparse.ArgumentParser(description="--== Kippo Scanner ==--", usage="./kipposcan.py [options]")
    parser.add_argument('-f', '--file', help='Specify a list of IPs and Ports in a file. Needs to be a single line consisiting of \"IP:Port\"', action='store', dest='file')
    parser.add_argument('-i', '--ip', help='IP Address of a suspected Kippo Honeypot', action='store', dest='ip')
    parser.add_argument('-p', '--port', help='Port of the suspected Kippo Honeypot', action='store', dest='port', default=22)
    parser.add_argument('-v', '--verbose', help='Turns on verbose mode', action='store_true', dest='verbose')
    parser.add_argument('-w', '--write', help='Write the sucessful results to file', action='store', dest='writefile')
    global args
    args = parser.parse_args()

    if not args.ip and not args.file:
        parser.print_help()
        print "\n[!] You must specifiy either IP address or file of IP addresses"
        sys.exit(0)

    if args.ip and args.file:
        parser.print_help()
        print "\n[!] Can not specify both filename and IP address. Its one or the other"
        sys.exit(0)

def parsefile(line):
    if ":" in line:
        ip = line.split(":", 1)[0]
        portstr = line.split(":", 1)[1]
        port = int(portstr)
        tests(ip, port)
    if not ":" in line:
        ip = line.strip()
        tests(ip, 22)

def tests(ip, port):
    results1 = bannergrab(ip, port)
    results2 = test_protocolmismatch(ip,port)
#    if args.verbose == True:
#        print "[+] Test 3: Attempting login"
#    login(ip,port,score)
    report(ip, port, results1, results2)

def bannergrab(ip, port):
    ''' Check the banner for consistency with kippo '''

    score = 0
    s = socket.socket()
    s.settimeout(10)

    try:
        s.connect((ip, port))
        reply = s.recv(30)
        s.close()
    except Exception as e:
        reply = "Error: " + str(e)

    if "SSH-2.0-OpenSSH_5.1p1 Debian-5" in reply:
        score += 50

    return (score, reply)

def test_protocolmismatch(ip, port):
    ''' Test daemon\'s reply to nonSSH traffic '''

    score = 0
    command = "DC801"
    s = socket.socket()
    s.settimeout(10)

    try:
        s.connect((ip, port))
        s.send(command*50)
        s.send("\n")
        reply = s.recv(512)
        s.close()
    except Exception as e:
        reply = "Error: " + str(e)

    if len(reply) != 0 and "Error: " not in reply:
        if "Protocol mismatch" not in reply:
            score += 100

    return (score, reply)

def login(ip,port,score):
    spawncmd = "ssh -p " + str(port) + " root@" + ip
    p = pexpect.spawn(spawncmd)

    log = file('pexpect.log','wb')
    p.logfile = log

    i = p.expect(['Are you sure you want to continue connecting', '.*[Pp]assword.*', pexpect.EOF])
    if i == 0:
        p.sendline('yes')
        i = p.expect(['Are you sure you want to continue connecting', '.*[Pp]assword.*', pexpect.EOF])
    if i == 1:
        p.sendline("123456")
        p.expect(".*")
    if i == 2:
        if arg.verbose == True:
            print "[!] Error connecting"
        sys.exit(0)
    p.expect(".*")
    p.sendline('\003')
    p.sendline('\003')
    p.sendline('\003')
    time.sleep(3)
    p.sendline("hostname")
    hostnamefile = file('kippo-hostname', 'w+b')
    p.expect(".*")
    os.popen("rm -f kippo-hostname")
    time.sleep(3)
    p.sendline("ifconfig")
    time.sleep(3)
    p.expect(".*")
    p.sendline("ifconfig")
    time.sleep(3)
    p.expect(".*")
    p.sendline("cat /etc/passwd")
    time.sleep(3)
    p.expect(".*")

def parsepexpect():
    f = open('pexpect.txt', 'r')
    hostname = re.compile('.*nas3:~#.*')

def report(ip, port, results1, results2):
    ''' Handle formatting and print output '''

    score1 = results1[0]
    reply1 = results1[1]
    score2 = results2[0]
    reply2 = results2[1]
    score = score1 + score2

    print "[+] Checking: " + ip + ":" + str(port)
    print "[+] Test 1: Banner Grab"
    print "[*]   Banner received: "
    print "         " + reply1.strip()
    if score1 == 50:
        print "[*]   Banner was consistent with Kippo"
    else:
        print "[*]   Banner was NOT consistent with Kippo"
    print "[*]   Score after banner test: " + str(score1)

    print "[+] Test 2: Protocol mismatch"
    print "[*]   Score after protocol mismatch test: " + str(score2)

    print "\n          [REPORT]"
    if score >= 150:
        print ip + ":" + str(port) + " is a Kippo Honeypot"
        if args.writefile:
            log = ip + ":" + str(port) + "\n"
            with open(args.writefile, "a+") as f:
                f.write(log)

    if score < 100:
        if args.verbose:
            print ip + ":" + str(port) + " is NOT a Kippo Honeypot"
    if 100 < score < 150:
        if args.verbose:
            print ip + ":" + str(port) + " might be a Kippo Honeypot. Not 100%"
    print ""

def main():

    args()
    banner()
    in_parallel = 1000
    pool = Pool(in_parallel)

    if args.file:
        with open(args.file, "r") as f:
            jobs = [pool.spawn(parsefile, line) for line in f]
            joinall(jobs)

    elif args.ip:
        ip = args.ip
        port = int(args.port)

        if args.verbose:
            print "[+] Checking: " + ip + ":" + str(port)
        tests(ip, port)

main()
