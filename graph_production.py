'''
Graph Production Module

Contains all functions for:
	- sorting data produced during training/optimisation
	- generating and saving plots
	- provide statistics about labels
'''

def class_balance_binary(labels):
	normal = 0
	abnormal = 0
	total = 0
	for i in labels:
		if i == 1:
			abnormal += 1
		else:
			normal += 1
		total += 1

	return((normal/total), (abnormal/total))