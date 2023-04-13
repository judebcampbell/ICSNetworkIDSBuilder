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


def SWATlabels(openfilename):
	labels = []
	df = pd.read_csv(openfilename)
	print(df.head(5))
	print(df.columns)
	for index, row in df.iterrows():
		numb = row[' Timestamp'].split()
		#print(numb)
		am = numb[-1]
		d = numb[0]
		numb = numb[1].split(":")
		if am == 'AM':
			am = True
		else:
			am = False
		
		#print(numb)
		# attacl 1 and 2
		if d == '28/12/2015' and numb[0] == '10' and am == True:
			print(numb)
			if (int(numb[1]) > 29 and int(numb[1]) < 44) or (int(numb[1]) > 51 and int(numb[1]) < 58):
				labels.append(1)
				continue
			elif int(numb[1]) == 29 and int(numb[2]) > 13:
				labels.append(1)
				continue
			elif int(numb[1]) == 51 and int(numb[2]) > 7:
				labels.append(1)
				continue
			elif int(numb[1]) == 44 and int(numb[2]) < 54:
				labels.append(1)
				continue
			elif int(numb[1]) == 58 and int(numb[2]) < 31:
				labels.append(1)
				continue
		
		# attack 3 and 4
		if d == '28/12/2015' and numb[0] == '11' and am == True:
			if (int(numb[1]) >= 22 and int(numb[1]) < 28) or (int(numb[1]) > 47 and int(numb[1]) < 54):
				labels.append(1)
				continue
			elif int(numb[1]) == 47 and int(numb[2]) > 38:
				labels.append(1)
				continue
			elif int(numb[1]) == 28 and int(numb[2]) < 23:
				labels.append(1)
				continue
			elif int(numb[1]) == 54 and int(numb[2]) < 9:
				labels.append(1)
				continue
		
		# attack 13 and 14
		if d == '29/12/2015' and numb[0] == '11' and am == True:
			if (int(numb[1]) > 11 and int(numb[1]) < 15) or (int(numb[1]) > 35 and int(numb[1]) < 42):
				labels.append(1)
				continue
			elif int(numb[1]) == 11 and int(numb[2]) > 24:
				labels.append(1)
				continue
			elif int(numb[1]) == 35 and int(numb[2]) > 39:
				labels.append(1)
				continue
			elif int(numb[1]) == 15 and int(numb[2]) < 18:
				labels.append(1)
				continue
			elif int(numb[1]) == 42 and int(numb[2]) < 51:
				labels.append(1)
				continue
		
		# attack 17
		# 29/12/2015 14:38:12	14:50:08
		if d == '29/12/2015' and numb[0] == '2' and am == False:
			if (int(numb[1]) > 38 and int(numb[1]) < 50):
				labels.append(1)
				continue
			elif int(numb[1]) == 38 and int(numb[2]) > 11:
				labels.append(1)
				continue
		
		# attack 21
		# 29/12/2015 18:30:00	18:42:00
		if d == '29/12/2015' and numb[0] == '6' and am == False:
			if (int(numb[1]) > 29 and int(numb[1]) < 42):
				labels.append(1)
				continue
		
		# attack 22
		# 29/12/2015 22:55:18	23:03:00
		if d == '29/12/2015' and am == False and (numb[0] == '10' or numb[0] == '11'):
			if numb[0] == '10' and (int(numb[1]) > 55):
				labels.append(1)
				continue
			elif int(numb[0]) == 10 and int(numb[1]) == 55 and int(numb[1]) > 17:
				labels.append(1)
				continue
			elif int(numb[0]) == 11 and int(numb[1]) < 3:
				labels.append(1)
				continue
		
		# attack 23
		#30/12/2015 01:42:34	01:54:10
		if d == '30/12/2015' and numb[0] == '1' and am == True:
			if (int(numb[1]) > 42 and int(numb[1]) < 54):
				labels.append(1)
				continue
			elif int(numb[1]) == 42 and int(numb[2]) > 33:
				labels.append(1)
				continue
			elif int(numb[1]) == 54 and int(numb[2]) < 11:
				labels.append(1)
				continue

		# attack 24
		# 30/12/2015 09:51:08	09:56:28		
		if d == '30/12/2015' and numb[0] == '9' and am == True:
			if (int(numb[1]) > 51 and int(numb[1]) < 56):
				labels.append(1)
				continue
			elif int(numb[1]) == 51 and int(numb[2]) > 7:
				labels.append(1)
				continue
		
		# attack 25
		# 30/12/2015 10:01:50	10:12:01
		if d == '30/12/2015' and numb[0] == '10' and am == True:
			if (int(numb[1]) > 1 and int(numb[1]) < 12):
				labels.append(1)
				continue
			elif int(numb[1]) == 1 and int(numb[2]) > 49:
				labels.append(1)
				continue
			elif int(numb[1]) == 12 and int(numb[2]) < 2:
				labels.append(1)
				continue

		# attack 26
		# 30/12/2015 17:04:56	17:29:00
		if d == '30/12/2015' and numb[0] == '5' and am == False:
			if (int(numb[1]) > 4 and int(numb[1]) < 29):
				labels.append(1)
				continue
			elif int(numb[1]) == 4 and int(numb[2]) > 33:
				labels.append(1)
				continue
		
		# attack 27 and 28
		# 31/12/2015 01:17:08	01:45:18
		# 31/12/2015 01:45:19	11:15:27
		if d == '31/12/2015' and am == True and (1 <= int(numb[0]) < 12):
			if (int(numb[0]) == 1 and 17 > int(numb[1])):
				labels.append(0)
				continue
			elif int(numb[0]) == 11 and int(numb[1]) == 15 and int(numb[2]) > 27:
				labels.append(0)
				continue
			elif int(numb[0]) == 11 and int(numb[1]) > 15:
				labels.append(0)
				continue
			else:
				labels.append(1)
				continue
		
		# Attacks 29 and 30
		# 31/12/2015 15:32:00	15:34:00
		# 31/12/2015 15:47:40	16:07:10
		if d == '31/12/2015' and numb[0] == '3' and am == False:
			if (int(numb[1]) > 31 and int(numb[1]) < 34):
				labels.append(1)
				continue
			elif int(numb[1]) > 47:
				labels.append(1)
				continue
			elif int(numb[1]) == 47 and int(numb[2]) > 39:
				labels.append(1)
				continue
		if d == '31/12/2015' and numb[0] == '4' and am== False:
			if int(numb[1]) < 7:
				labels.append(1)
				continue

		# Attacks 34 and 35
		# 1/01/2016 17:12:40	17:14:20
		# 1/01/2016 17:18:56	17:26:56
		if d == '1/1/2016' and numb[0] == '5' and am == False:
			if (int(numb[1]) > 12 and int(numb[1]) < 14) or (int(numb[1]) > 18 and int(numb[1]) < 26):
				labels.append(1)
				continue
			elif int(numb[1]) == 12 and int(numb[2]) > 39:
				labels.append(1)
				continue
			elif int(numb[1]) == 18 and int(numb[2]) > 55:
				labels.append(1)
				continue
			elif int(numb[1]) == 14 and int(numb[2]) < 21:
				labels.append(1)
				continue
			elif int(numb[1]) == 26 and int(numb[2]) < 57:
				labels.append(1)
				continue

		labels.append(0)
	
	return(labels)


filename = 'SWAT_attack'
labels = SWATlabels('data/evaluation/SWAT_attack.csv')
print(len(labels))

classfilename = 'data/evaluation/' + filename + 'Class.txt'

print(pg.class_balance_binary(labels))

with open(classfilename, 'w') as f:
	for l in labels:
		f.write(str(l)+ "\n")