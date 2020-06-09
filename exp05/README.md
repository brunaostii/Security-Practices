# Exp05 HTTP-Dissector

A network dissector is a protocol decoder. It is the implementation 
of some understanding of a given protocol to allow the extraction of
specific information from its messages.
For example, an FTP dissector applied to a certain traffic should
understand the messages related to this protocol. With the dissector
implemented correctly, it would be possible to extract even a file
transferred via FTP during a connection.

This task's goal is for the group to develop an HTTP dissector
allowing reassembly (extracting) the files transferred during sessions
of the protocol. In addition to the dissector, each group must write
a brief report describing the implementation and decisions taken during
the development and testing phases.

 - The dissector should be done in Python.
 - The dissector should read as argument a file in pcap
	 format (e.g. $ python http-dissector.py -r mytraffic.pcap)
 - The validation tests for grading will check, among other things,
 if the dissector can extract PE-32 Windows executable files and textual files.
 - The program should compile correctly at the time of grading.
 Failing to do that will yield a 0 (Zero) in the experiment.
