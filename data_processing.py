'''
data_processing module

contains all functinos necessary to pre-process data
'''


import numpy as np
import pandas as pd


'''
Function to read in target classes into a list
'''
def targetReader(filename):
	targets = []
	with open(filename, "r") as f:
		for line in f:
			targets.append(int(line.strip()))
	
	return(targets)

'''Function takes read pcap/pcapng file and generates feature vectors
		file - opened pcap/pcapng with Scapy
		labels - opened class labes for each packet in file
		windowSize - size of the rolling window to be considered 

	over a rolling window:
		 Total # bytes transfered 				Avg packet size in bytes
		 Smallest packet 						Largest packet
		 number of packets at 128 B intervals (7 fields)
		 # of unique sources 					# of unique destinations
		 # duration of the window				# average interarrival time of the packets
		 # of unique TCP Flags
output is a pandas dataframe + targets as a list
'''
def rollingWindow(file,label, windowSize=20):
	counter = windowSize - 1
	maxVal = len(file)
	rows = []

	#number of bytes in each packet
	bytesTransfered = []

	#smallest and largest packet transfered in the window
	smallest = 1200
	largest = 0 

	#no packets between different sizes
	packets128, packets128To256, packets256To512, = 0,0,0
	packets512To1024, packets1024To1514, packetsAbove1514 = 0, 0, 0
	
	#number of sources and destinations
	sources =  []
	destinations = []

	#number of TCP flags and arrival times
	tcp_flags = []
	arrivals = []

	duration = 0

	#output labels for each vector
	labelQueue = []
	targets = []

	# Populate the queues with initial values
	for i in range(counter):
		bytesTransfered.append(len(file[i]))
		sources.append(file[i]['IP'].src)
		destinations.append(file[i]['IP'].dst)
		tcp_flags.append(file[i]['TCP'].flags)
		arrivals.append(file[i].time)
		labelQueue.append(label[i])
	

	while maxVal - counter > windowSize:
		# Increase counter and add output update
		counter +=1
		if counter % 10000 == 0:
			print("on element: " + str(counter))

		#skip packet adding and information if it is missing necessary information
		if IP not in file[counter] or TCP not in file[counter]:
			continue

		#add next package to the queue
		bytesTransfered.append(len(file[counter]))
		sources.append(file[counter]['IP'].src)
		destinations.append(file[counter]['IP'].dst)
		tcp_flags.append(file[counter]['TCP'].flags)
		arrivals.append(file[counter].time)

		# Calculate Summary statistics for the current queue
		#total no bytes transfered in window
		totalBytes = sum(bytesTransfered)
		avgBytes = totalBytes / windowSize

		smallest =  min(bytesTransfered)
		largest = max(bytesTransfered)

		packets128 = len(list(x for x in bytesTransfered if x <= 128))
		packets128To256 = len(list(x for x in bytesTransfered if 128 < x <= 256))
		packets256To512 = len(list(x for x in bytesTransfered if 256 < x <= 512))
		packets512To1024 = len(list(x for x in bytesTransfered if 512 < x <= 1024))
		packets1024To1514 = len(list(x for x in bytesTransfered if 1023 < x <= 1514))
		packetsAbove1514 = len(list(x for x in bytesTransfered if 1514 < x))
		
		noSources = len(set(sources))
		noDestinations = len(set(destinations))
		noTCPFlags = len(set(tcp_flags))
		duration = max(arrivals) - min(arrivals) 
		interArrival = duration / windowSize
		
		if 1 in labelQueue:
			targets.append(1)
		else:
			targets.append(0)

		#compose array row
		row = [totalBytes, avgBytes, smallest, largest, packets128, packets128To256, 
			   packets256To512, packets512To1024, packets1024To1514, packetsAbove1514, 
			   noSources, noDestinations, noTCPFlags, duration, interArrival]
		rows.append(row) 

		#delete first element from the list
		bytesTransfered.pop()
		sources.pop()
		destinations.pop()
		tcp_flags.pop()
		arrivals.pop()

	#Return the rows of summary vectors
	features = pd.DataFrame(rows, columns=["Total Bytes Transfered", "Avg Bytes per Packet", 
									"smallest Packet", "Largest Packet", "packets < 128 ", 
									"packets 128 to 256", "packet 256 to 512", "packets 512 to 1024",
									 "packets 1024 to 1514", "packets > 1514", "No sources", 
									 "no destinations", "no TCP Flags", "duration", "inter arrival time"]
							)
	return(features, targets)


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
def timestamps(file, labels, frequency=20):
	rows = []
	# total time of the pcap and total number of packets transmitted
	total_time = file[len(file)-1].time - file[0].time
	total_packets = len(file) - 1

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
				counter += 1
				continue


			if file[counter]['IP']:
				packet_type.append(file[counter]['IP'].proto)
				if file[counter]['TCP']:
					tcp_flags.append(file[counter]['TCP'].flags)
			else:
				packet_type.append(file[counter]['Ethernet'].type)
			
			

			labelQueue.append(labels[label_counter])

			if counter == total_packets or counter-1 == total_packets:
				break
			
			counter += 1
			label_counter += 1
			if counter % 10000 == 0:
				print("On packet:" + str(counter))
				
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
		noDestinations = len(set(sources))
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
			  noSources, noDestinations, uniqueIps, NoTCP, noProtcols, 
				packetCount, avgInterArrival
			]

		#add target class for current time
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
									"Largest Packets", '25%', '50%', '75%', "No Sources", "No of Destinations", 
									"No IPs", "No TCP Flags", "No Protocols", "Packet Count", "Average Inter Arrival Time"]
							)

	return(features, targets)

