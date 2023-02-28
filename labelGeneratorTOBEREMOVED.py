from scapy.all import *
import graph_production as pg

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

def l5AttackGenerator(openfilename):
	openfile = rdpcap(openfilename)
	labels = []
	#totalLength = int(len(openfile))
	openfile[0].show()
	for pkt in openfile:
		if IP not in pkt or TCP not in pkt:
			if ARP in pkt:
				labels.append(1)
			else:
				labels.append(0)
			continue



		if pkt['IP'].src == "ASUSTekC_13:0b:13":
			labels.append(1)
		elif pkt['IP'].proto == "ARP":
			print("FOUND")
			labels.append(1)
		elif pkt['IP'].src == "192.168.5.90" and pkt["IP"].dst == "192.168.5.109":
			labels.append(1)
		elif pkt['IP'].src == "192.168.5.109":
			labels.append(1)
		else:
			labels.append(0)
	
	return(labels)

def l5AttackClassifier(openfilename):
	openfile = rdpcap(openfilename)
	labels = []
	count = 0
	totalLength = int(len(openfile))

	for pkt in openfile:
		if pkt.time < 180:
			labels.append(0)
			continue
		elif 300 < pkt.time < 600:
			labels.append(0)
			continue
		elif 780 < pkt.time < 960:
			labels.append(0)
			continue
		elif 1020 < pkt.time < 1080:
			labels.append(0)
			continue
		elif 1140 < pkt.time < 1200:
			labels.append(0)
			continue
		elif 1260 < pkt.time < 1380:
			labels.append(0)
			continue
		elif 1500 < pkt.time < 1980:
			labels.append(0)
			continue
		elif 2160 < pkt.time < 2280:
			labels.append(0)
			continue
		elif 2340 < pkt.time <  2520:
			labels.append(0)
			continue

		if 'IP' in pkt:
			if pkt['IP'].src == "192.168.5.100":
				labels.append(1)
				continue
			elif pkt['IP'].src == '192.168.5.40' and pkt['Ethernet'] == '8:32:e4:bc:c0:5f':
				labels.append(1)
				continue
			elif pkt['IP'].src == '192.168.5.104' and pkt['IP'].dst == '192.168.5.22' and pkt['IP'].proto == 'S7Comm':
				print('found S7')
				labels.append(1)
				continue
			
		else:
			if 'Ethernet' in pkt:
				if pkt['Ethernet'].dst == 'ff:ff:ff:ff:ff:ff':
					labels.append(1)
					continue
		
		labels.append(0)

	return(labels)

def l5AttackClassifierEVALUATION(openfilename):
	openfile = rdpcap(openfilename)
	labels = []
	count = 0
	totalLength = int(len(openfile))

	for pkt in openfile:
		if 'IP' in pkt:
			if pkt['IP'].src == "192.168.5.100":
				labels.append(1)
				continue
			elif pkt['IP'].src == '192.168.5.40' and pkt['Ethernet'] == '8:32:e4:bc:c0:5f':
				labels.append(1)
				continue
			elif pkt['IP'].src == '192.168.5.104' and pkt['IP'].dst == '192.168.5.22' and pkt['IP'].proto == 'S7Comm':
				print('found S7')
				labels.append(1)
				continue
			
		else:
			if 'Ethernet' in pkt:
				if pkt['Ethernet'].dst == 'ff:ff:ff:ff:ff:ff':
					labels.append(1)
					continue
		
		labels.append(0)

	return(labels)

# Generate Labels for clean data sets
def cleanLabels(openfilename):
	openfile = rdpcap(openfilename)
	labels = []

	for pkt in openfile:
		labels.append(0)
	
	return(labels)

filename = 'cleanTest'
labels = cleanLabels('data/timestamps/cleanTest.pcapng')

classfilename = 'data/timestamps/' + filename + 'Class.txt'

print(pg.class_balance_binary(labels))

with open(classfilename, 'w') as f:
	for l in labels:
		f.write(str(l)+ "\n")
	
