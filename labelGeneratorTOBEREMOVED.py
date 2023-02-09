from scapy.all import *

def l4AttackGenerator(openfilename):
	openfile = rdpcap(openfilename)
	labels = []
	#totalLength = int(len(openfile))
	for pkt in openfile:
		if IP not in pkt or TCP not in pkt:
			labels.append(0)
			continue


		if pkt['IP'].src == "192.168.5.64" and pkt["IP"].dst == "192.168.5.63":
			labels.append(1)
		elif pkt['IP'].src == "192.168.5.93" and pkt["IP"].dst == "192.168.5.63":
			labels.append(1)
		elif pkt['IP'].src == "192.168.5.63" and pkt["IP"].dst == "192.168.5.93":
			labels.append(1)
		elif pkt['IP'].src == "192.168.5.63" and pkt["IP"].dst == "192.168.5.64":
			labels.append(1)
		else:
			labels.append(0)
	
	return(labels)

filename = 'CaptureW64'
labels = l4AttackGenerator('data/initial_tests/CaptureW64.pcapng')

classfilename = 'data/initial_tests/' + filename + 'TARGETS.txt'

with open(classfilename, 'w') as f:
	for l in labels:
		f.write(str(l)+ "\n")
	
