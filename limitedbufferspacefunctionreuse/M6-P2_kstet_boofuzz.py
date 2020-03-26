# Author: Uday Mittal
# Company: Yaksas CSC
# Contact: csc@yaksas.in | twitter.com/yaksas443

from boofuzz import *
d

def main():

	f = open('vulns-fuzz.csv', 'wb')
	

	start_cmd = ['C:\\Users\\PT LabMachine\\Desktop\\vulnserver\\vulnserver.exe']
	target_ip = "192.168.43.247"
	session = Session(
		target=Target(
			connection=SocketConnection(target_ip,9999,proto='tcp'),
			procmon=pedrpc.Client(target_ip,26002),
			procmon_options={"start_commands": [start_cmd]}
		),
		sleep_time=1,
		fuzz_loggers=[FuzzLoggerText(),FuzzLoggerCsv(file_handle=f)]
		)


	s_initialize("kstet")
	s_static("KSTET")
	s_delim(" ",fuzzable=False)
	s_string("test")
	s_static("\r\n")

	session.connect(s_get("kstet"))

	session.fuzz()


if __name__=="__main__":
	main()