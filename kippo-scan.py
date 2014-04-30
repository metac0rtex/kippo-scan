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
        if args.verbose == True:
            print "[+] Checking: " + ip + ":" + str(port)
        tests(ip, port)
    if not ":" in line:
        ip = line.strip()
        if args.verbose == True:
            print "[+] Checking: " + ip + ":22"
        tests(ip, 22)


def tests(ip, port):
    global score
    score = 0
    if args.verbose == True:
        print "[+] Test 1: Banner Grab"
    bannergrab(ip, port)
    if args.verbose == True:
        print "[+] Test 2: Protocol mismatch"
    test_protocolmismatch(ip,port)
    if args.verbose == True:
        print "  [+] Score after Test 1: " + str(score)
#    if args.verbose == True:
#        print "[+] Test 3: Attempting login"
#    login(ip,port)
    report(ip, port)

def bannergrab(ip, port):
    global score

    if args.verbose == True:
        print "  [+] Making raw socket connect to " + ip + ":" + str(port)
    s = socket.socket()
    s.settimeout(10)
    try:
        s.connect((ip, port))
        reply = s.recv(30)
        print "    [+] Banner we got was: "
        print "      " + reply.strip()
        s.close()
        if "SSH-2.0-OpenSSH_5.1p1 Debian-5" in reply:
            print "    [+] Banner was consistent with Kippo"
            score += 50
        else:
            print "    [-] Banner was not consistent with Kippo"

    except Exception, e:
        print e


def test_protocolmismatch(ip, port):
    global score

    command = "DC801"
    if args.verbose == True:
        print "  [+] Making raw socket connect to " + ip + ":" + str(port)
    s = socket.socket()
    try:
        s.connect((ip, port))
        s.settimeout(10)
        reply = s.recv(512)
        if reply:
            if args.verbose == True:
                print "    [+] Banner we got was: "
                print "      " +  str(reply).strip()
        if args.verbose == True:
            print "    [+] Sending non SSH traffic"

        s.send(command*50)
        s.send("\n")
        reply = s.recv(512)

        if "Protocol mismatch" not in reply:
            if args.verbose == True:
                print "      [+] Did not give us \"protocol mismatch\" error"
                print "        [+] This is irregular"
            score += 100
        if "Protocol mismatch" in reply or len(reply) == 0:
            if args.verbose == True:
                print "      [-] Gave us \"protocol mismatch\" error or nothing back."
                print "        [-] Seems to be a real SSH daemon"

    except Exception, e:
        print e

def login(ip,port):
    global score
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
    global score
    f = open('pexpect.txt', 'r')
    hostname = re.compile('.*nas3:~#.*')


def report(ip, port):
    global score
    print "\n[REPORT]"
    print "Current score is " + str(score)
    if score >= 150:
        print ip + ":" + str(port) + " is a Kippo Honeypot"
        if args.writefile:
            log = ip + ":" + str(port) + "\n"
            with open(args.writefile, "a+") as f:
                f.write(log)

    if score < 100:
        print ip + ":" + str(port) + " is NOT a Kippo Honeypot"
    if 100 < score < 150:
        print ip + ":" + str(port) + " might be a Kippo Honeypot. Not 100%"
    print ""

def main():
    global score

    args()
    banner()
    pool = Pool(1000)

    score = 0

    if args.file:
        with open(args.file, "r") as f:
            jobs = [pool.spawn(parsefile, line) for line in f]
            joinall(jobs)

    else:
        ip = args.ip
        port = int(args.port)

        print "[+] Checking: " + ip + ":" + str(port)

        tests(ip, port)

main()
