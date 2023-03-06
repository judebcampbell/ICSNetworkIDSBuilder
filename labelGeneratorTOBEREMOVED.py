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
	
		if 'IP' in pkt:
			if pkt['IP'].src == "192.168.5.100":
				labels.append(1)
				continue
			elif pkt['IP'].src == '192.168.5.40' and pkt['Ethernet'].src == 'f8:32:e4:bc:c0:5f':
				print('DOS found')
				labels.append(1)
				continue
			elif pkt['IP'].dst == '192.168.5.22' and pkt["Ethernet"].src == 'f8:32:e4:bc:c0:5f':
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
				if pkt['Ethernet'].src == 'f8:32:e4:bc:c0:5f' and len(pkt) == 73:
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


filename = 'training52Minutes'
labels = l5AttackClassifier('data/timestamps/training52Minutes.pcapng')

classfilename = 'data/timestamps/' + filename + 'Class.txt'

print(pg.class_balance_binary(labels))

with open(classfilename, 'w') as f:
	for l in labels:
		f.write(str(l)+ "\n")

with open("data/timestamps/training52MinutesClass.txt") as file:
    generated = [int(line.strip()) for line in file]

new = []

for i in range(len(generated)):
	if i < 4940:
		print(i)
		new.append(int(0))
		continue
	elif 8318 < i < 11609:
		new.append(int(0))
		continue
	elif 25415 < i < 33501:
		new.append(int(0))
		continue
	elif 38441 < i < 48195:
		new.append(int(0))
		continue
	elif 100282 < i < 101850:
		new.append(int(0))
		continue
	elif 103543 < i < 106860:
		new.append(int(0))
		continue
	elif 211503 < i < 214666:
		new.append(int(0))
		continue
	elif 216286 < i < 217931:
		new.append(int(0))
		continue
	elif 219568 < i < 224328:
		new.append(int(0))
		continue
	elif 325427 < i < 328624:
		new.append(int(0))
		continue
	else: 
		new.append(int(generated[i]))

print('Original Class Imbalance')	
print(pg.class_balance_binary(generated))
print('Cleaned Class Imbalance')
print(pg.class_balance_binary(new))

filename = 'training52MinutesPOLISHED'

classfilename = 'data/timestamps/' + filename + 'Class.txt'
with open(classfilename, 'w') as f:
	for l in new:
		f.write(str(l)+ "\n")