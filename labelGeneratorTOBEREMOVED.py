from scapy.all import *
import numpy as np 
import pandas as pd
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


def WADILabeler(openfilename):
	labels = []
	df = pd.read_csv(openfilename)
	for index, row in df.iterrows():
		numb = row['Time'].split()
		am = numb[-1]
		numb = numb[0].split(":")
		x = numb[2][:2]
		x = int(x)
		if am == 'AM':
			am = True
		else:
			am = False

		if row['Date'] == '10/9/2017' and numb[0] == '7' and am == False:
			if int(numb[1]) >= 25 and int(numb[1]) < 50:
				print('9th attack s')
				labels.append(1)
				continue
			elif int(numb[1]) == 50 and int(numb[2][:2]) < 16:
				labels.append(1)
				continue
		
		if row['Date'] == '10/10/2017' and numb[0] == '10':
			if int(numb[1]) > 24 and int(numb[1]) < 34:
				labels.append(1)
				continue
			elif int(numb[1]) == 24 and int(numb[2][:2]) > 10:
				labels.append(1)
				continue
			elif int(numb[1]) >= 55:
				labels.append(1)
				continue
			
		if row['Date'] == '10/10/2017' and numb[0] == '11' and int(numb[2][:2]) < 24:
				labels.append(1)
				continue

		if row['Date'] == '10/10/2017' and numb[0] == '11':
			if (30 < int(numb[1]) < 44):
				labels.append(1)
				continue
			elif int(numb[2][:2]) >= 40 and int(numb[1]) == 30:
				labels.append(1)
				continue
			elif int(numb[2][:2]) <=50 and int(numb[1]) == 44:
				labels.append(1)
				continue

		if row['Date'] == '10/10/2017' and numb[0] == '1' and am == False:
			if (39 < int(numb[1]) < 50):
				labels.append(1)
				continue
			elif int(numb[2][:2]) >= 30 and int(numb[1]) == 39:
				labels.append(1)
				continue
			elif int(numb[2][:2]) <=40 and int(numb[1]) == 50:
				labels.append(1)
				continue

		if row['Date'] == '10/10/2017' and numb[0] == '2' and am == False:
			if (48 < int(numb[1]) < 59):
				labels.append(1)
				continue
			elif int(numb[2][:2]) >= 17 and int(numb[1]) == 38:
				labels.append(1)
				continue
			elif int(numb[2][:2]) <=55 and int(numb[1]) == 59:
				labels.append(1)
				continue

		if row['Date'] == '10/10/2017' and numb[0] == '5' and am == False:
			if (40 <= int(numb[1]) < 49):
				labels.append(1)
				continue
			elif int(numb[2][:2]) <=40 and int(numb[1]) == 49:
				labels.append(1)
				continue

		if row['Date'] == '10/11/2017' and numb[0] == '10':
			if (55 <= int(numb[1]) < 56):
				labels.append(1)
				continue
			elif int(numb[2][:2]) <=27 and int(numb[1]) == 56:
				labels.append(1)
				continue

		if row['Date'] == '10/11/2017' and numb[0] == '11':
			if (17 < int(numb[1]) < 31):
				labels.append(1)
			elif int(numb[2][:2]) >= 54 and int(numb[1]) == 17:
				labels.append(1)
				continue
			elif int(numb[2][:2]) <=20 and int(numb[1]) == 31:
				labels.append(1)
				continue

		if row['Date'] == '10/11/2017' and numb[0] == '11':
			if (36 < int(numb[1]) < 47):
				labels.append(1)
				continue
			elif int(numb[2][:2]) >= 31 and int(numb[1]) == 36:
				labels.append(1)
				continue
			elif int(numb[1]) == 59:
				labels.append(1)
				continue

		if row['Date'] == '10/11/2017' and (numb[0] == '12'):
			if int(numb[1]) < 5:
				labels.append(1)
				continue
			if (7 < int(numb[1]) < 10):
				labels.append(1)
				continue
			elif int(numb[2][:2]) >= 30 and int(numb[1]) == 7:
				labels.append(1)
				continue
			elif int(numb[2][:2]) <=52 and int(numb[1]) == 10:
				labels.append(1)
				continue

		if row['Date'] == '10/11/2017' and numb[0] == '12':
			if (16 <= int(numb[1]) < 25):
				labels.append(1)
				continue
			elif int(numb[2][:2]) <=36 and int(numb[1]) == 25:
				labels.append(1)
				continue

		if row['Date'] == '10/11/2017' and numb[0] == '3' and am == False:
			if (26 < int(numb[1]) < 37):
				print('attack')
				labels.append(1)
				continue
			elif int(numb[2][:2]) >= 30 and int(numb[1]) == 26:
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


filename = 'WADI_attackdata'
labels = WADILabeler('data/evaluation/WADI_attackdata.csv')
print(len(labels))

classfilename = 'data/evaluation/' + filename + 'Class.txt'

print(pg.class_balance_binary(labels))

with open(classfilename, 'w') as f:
	for l in labels:
		f.write(str(l)+ "\n")