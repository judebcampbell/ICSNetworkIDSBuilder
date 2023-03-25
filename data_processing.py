'''
data_processing module

contains all functinos necessary to pre-process data
'''


import numpy as np
import pandas as pd

import graph_production as gp
'''
Function to read in target classes into a list
'''
def targetReader(filename):
	targets = []
	with open(filename, "r") as f:
		for line in f:
			targets.append(int(line.strip()))
	
	return(targets)

'''Function automatically calculates the desired size for the timestamp window
'''
def timestampSize(file,label, windowSize=20):
	total_time = file[len(file)-1].time - file[0].time
	total_packets = len(file) - 1
	starter = np.arange(start=2, stop=total_time/60, step=2)
	l = [0.5, 1]
	for i in range(len(starter)):
		x = starter[i]
		if x <= 10:
			l.append(int(x))
		if x > 10 and x%5 == 0:
			l.append(x)

	times = []
	for i in range(len(file)):
		times.append(file[i].time)
	#print(times)
	mid = len(l) / 2

	timestampClasses = []
	for j in range(len(l)):
		print(l[j])
		t = l[j]
		timer = t
		attackFound = 0
		timestampLabels = []
		for i in range(len(times)):
			if i == 0:
				start = int(times[i])
			difference = int(times[i]) - start

			if difference % 100 == 0:
				print(difference)

			if timer > difference:
				if int(label[i]) == 1:
					attackFound = 1
			else:
				timestampLabels.append(attackFound)
				attackFound = 0
				timer += t
			
		timestampClasses.append(timestampLabels)
	

	final_eval = []
	ab = []
	for i in range(len(l)):
		normal, abnormal = gp.class_balance_binary(timestampClasses[i])
		if 0.18 < abnormal < 0.38:
			final_eval.append(l[i])
			ab.append(abnormal)

	return final_eval[-1]


'''
Function to Generate Features over the previous x seconds
		file - opened pcap/pcapng with Scapy
		labels - opened class labels for each packet in file
		frequency - time duration for each vector

Generates a feature vector at a frequency Calculating 17 features:
		Total Bytes 							Average packet size
		Smallest Packet							Largest Packet
		# packets in 128 B intervals (7)
		# of unique sources 					# of unique destinations
		# of unique IPs						Packet Count
		Average Interarrival Time. 				# of unique TCP Flags
Output = pandad dataframe + targets as a list
'''
def timestamps(file, labels=None, size=None):
	if labels == None and size == None:
		freq = 10
	elif size == None:
		frequency = timestampSize(file, labels)
	else: 
		frequency = size

	rows = []
	# total time of the pcap and total number of packets transmitted
	total_time = file[len(file)-1].time - file[0].time
	total_packets = len(file) - 1

	print(total_packets)
	counter = 0
	currentVectorTime = 0

	label_counter = 0
	targets = []
	
	while counter < total_packets:
		
		#reset start time for each new vector
		start_time = file[counter].time
		#sources and destinations for all packets
		sources = []
		destinations = []
		ip_src = []
		ip_dst = []

		#number of packets transferred
		packetCount = 0

		# number of bytes transfered
		bytesTransfered = []
		q1, q2, q3 = 0, 0, 0
		smallest = 12000
		largest = 0

		# tcp flags and arrvial times
		tcp_flags = []
		arrivals = []
		packet_type = []

		#labels
		labelQueue =  []

		#Collect relevant information from the packets in current timestamp
		while currentVectorTime < frequency:

			# Need to add handling of ARP packets 
			if 'Ethernet' in file[counter]:
				sources.append(file[counter]['Ethernet'].src)
				destinations.append(file[counter]['Ethernet'].dst)
				packetCount += 1
				arrivals.append(file[counter].time)
				bytesTransfered.append(len(file[counter]))
			else:
				labelQueue.append(labels[counter])
				#label_counter += 1
				counter += 1
				continue


			if 'IP' in file[counter]:
				packet_type.append(file[counter]['IP'].proto)
				ip_src.append(file[counter]['IP'].src)
				ip_dst.append(file[counter]['IP'].dst)
				if 'TCP' in file[counter]:
					tcp_flags.append(file[counter]['TCP'].flags)
			else:
				packet_type.append(file[counter]['Ethernet'].type)
			
			if counter == total_packets or counter-1 == total_packets:
				break

			if labels != None:
				try:
					labelQueue.append(labels[counter])
				except:
					labelQueue.append(0)
			counter += 1
				
			currentVectorTime = arrivals[-1] - start_time
		
		#Generate Features
		#total and average bytes 
		totalBytes = sum(bytesTransfered)
		try:
			avg_bytes = totalBytes / packetCount
			smallest = min(bytesTransfered)
			largest = max(bytesTransfered)
		except:
			avg_bytes = 0
			smallest, largest = 0, 0 
		
		# Quartiles
		q1, q2, q3 = np.percentile(bytesTransfered, [25, 50, 75]) 

		# No of unique sources and destinations
		noSources = len(set(sources))
		noDestinations = len(set(destinations))

		noIP_src = len(set(ip_src))
		noIP_dst = len(set(ip_dst))
		# No of unique Ips either SRC or DST
		uniqueIps = sources + destinations
		uniqueIps = len(set(uniqueIps))

		# No of unqiue TCP Flags and packet types
		NoTCP = len(set(tcp_flags))
		noProtcols = len(set(packet_type))

		# Average interarrival Time
		try:
			avgInterArrival = currentVectorTime /packetCount
		except:
			avgInterArrival = 0

		#Create Vector
		row = [totalBytes, avg_bytes, smallest, largest, q1, q2, q3, 
			  noSources, noDestinations, noIP_src, noIP_dst, uniqueIps, NoTCP, noProtcols, 
				packetCount, avgInterArrival
			]

		#add target class for current time
		if labels != None:
			if 1 in labelQueue:
				targets.append(1)
			else:
				targets.append(0)
			
		# Add Vector to list
		rows.append(row)
		#Reset vector time
		currentVectorTime = 0

	#Change the list of vectors into a Pandas dataframe
	features = pd.DataFrame(rows, columns=["Total Bytes", "Average Packet Size", "Smallest Packet", 
									"Largest Packets", '25%', '50%', '75%', "No Sources", "No of Destinations", "No of IP srcs", 'No of IP dsts', 
									"unique addresses", "No TCP Flags", "No Protocols", "Packet Count", "Average Inter Arrival Time"]
							)

	if labels != None:
		return(features, targets, frequency)
	
	return(features)

def electraTimestamps(file, labels):
	size = 100
	rows = []
	total_time = file['Time'].loc[len(file)-1] - file['Time'].loc[0]
	total_count = len(file)
	
	print(total_count)
	#print(labels)
	counter = 0
	label_counter = 0
	targets = []

	while counter < total_count:
		current_count = 0

		sources = []
		destinations = []
		ip_src = []
		ip_dst = []
		requests = 0

		#number of packets transferred
		packetCount = 0

		bytesTransfered = []
		q1, q2, q3 = 0, 0, 0
		smallest = 12000
		largest = 0
		totalBytes = 0

		# tcp flags and arrvial times
		errors = []
		addresses = []

		#labels
		labelQueue =  []

		time = int(file.loc[counter, 'Time'])

		while current_count < size and counter < total_count:
			sources.append(file.loc[counter, 'smac'])
			destinations.append(file.loc[counter, 'dmac'])
			ip_src.append(file.loc[counter, 'sip'])
			ip_dst.append(file.loc[counter, 'dip'])
			requests += int(file.loc[counter, 'request'])
			bytesTransfered.append(int(file.loc[counter, 'data']))
			labelQueue.append(labels[counter])
			errors.append(int(file.loc[counter, 'error']))
			addresses.append(int(file.loc[counter, 'address']))
			time = int(file.loc[counter, 'Time']) - time

			if counter == total_count or counter - 1 == total_count:
				break

			current_count += 1
			counter += 1
			if counter % 100000  == 0:
				print(counter)
		
		totalBytes = sum(bytesTransfered)
		try:
			avg_bytes = totalBytes / current_count
			smallest =  min(bytesTransfered)
			largest =  max(bytesTransfered)
		except:
			avg_bytes = 0
			smallest, largest = 0, 0 

		q1, q2, q3 = np.percentile(bytesTransfered, [25, 50, 75]) 
		noSources = len(set(sources))
		noDestinations = len(set(destinations))
		noIP_src = len(set(ip_src))
		noIP_dst = len(set(ip_dst))

		noErrors = len(set(errors))
		noAdd = len(set(addresses))

		row = [totalBytes, avg_bytes, smallest, largest, q1, q2, q3, 
			  noSources, noDestinations, noIP_src, noIP_dst, noErrors, 
			  noAdd, time
			]

		if 0 in labelQueue or 2 in labelQueue or 3 in labelQueue or 4 in labelQueue or 5 in labelQueue or 6 in labelQueue or 7 in labelQueue:
			targets.append(1)
		else:
			targets.append(0)
		
		rows.append(row)
		
	features = pd.DataFrame(rows, columns=["Total Bytes", "Average Packet Size", "Smallest Packet", 
									"Largest Packets", '25%', '50%', '75%', "No Sources", "No of Destinations", "No of IP srcs", 'No of IP dsts', 
									"No Errors", "No PLC addresses", "Time taken"]
							)
	print(len(features))
	return(features, targets)