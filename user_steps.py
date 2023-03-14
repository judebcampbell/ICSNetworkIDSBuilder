'''
user_steps module 

Contains different functions that combine the other modules into different user story steps
Functions are based of use case diagram
'''

'''
Function - supresses sklearn warnings from output. 
'''
# Removes warning from outputs - for cleaner viewing in terminal mode
def warn(*args, **kwargs):
    pass
import warnings
warnings.warn = warn

import os
import glob

import numpy as np
import pandas as pd

import data_processing as dp 
import model_selection as ms 
import model_files as fm
import graph_production as gp

from scapy.all import *
from threading import Thread

'''
Function for finding best model including data processing
'''
def fullToLive(file, targetFile):
	f =  open(('figures/outputText.txt'), "w")
	openedFile = rdpcap(file)
	labels = fm.toList(targetFile) # generate target list
	training, targets, freq = dp.timestamps(openedFile, labels) # transform training data and targets

	val = len(training)
	split = round(0.8 * len(training))
	trainX = training[:split]
	trainY = targets[:split]
	testX = training[split:]
	testY = targets[split:]

	print("\n class balance normal to abnormal in the original data")
	print(gp.class_balance_binary(labels))
	print("\n class balance normal to abnormal in the produced data")
	n, a =gp.class_balance_binary(targets)
	print(n, a)

	f.write("Training data size:   " + str(split) + "\n")
	f.write("Test data size:   " + str(val - split) + "\n")
	f.write("Feature vectors calculated every  " + str(freq) + '  seconds' + "\n")
	f.write("Class imbalance:" + "\n")
	f.write("	Normal:  " + str(n) + "\n")
	f.write("	Abnormal:  " + str(a) + "\n")

	
	model_names, results, pipelines = ms.trainModels(trainX, trainY) #train the initial models
	best_model_names = ms.evaluateModels(results, model_names, 3) # find the 3 best models
	tuned_model_names, tuned_results, tuned_models = ms.hyperparameterTuning(best_model_names, pipelines, trainX, trainY)
	final_name, final_model = ms.evaluateModels(tuned_results, tuned_model_names, 1, tuned_models)
	final_name = final_name[0]
	fm.saveBestModel(final_model, final_name, nameFile=False)

	gp.generatePlots(results, model_names, "Training")
	gp.generatePlots(tuned_results, tuned_model_names, "Optimised")
	

	return(model_names, results, tuned_model_names, tuned_results, freq)

'''
Function to find best model for data that does not need to be processed in the system
'''
def modelSelectionNoProcessing(file, targets):
	targets = fm.toList(targets)
	training = pd.read_csv(file)

	model_names, results, pipelines = ms.trainModels(training, targets) #train the initial models
	best_model_names = ms.evaluateModels(results, model_names, 3) # find the 3 best models
	tuned_model_names, tuned_results, tuned_models = ms.hyperparameterTuning(best_model_names, pipelines, training, targets)
	final_name, final_model = ms.evaluateModels(tuned_results, tuned_model_names, 1, tuned_models)
	final_name = final_name[0]
	fm.saveBestModel(final_model, final_name, nameFile=False)


'''
Function for live continous data captures on the relevant testbed
'''
def captureFunc():
	return("Capture Func")

'''
Function for predicting attacks and alerting user
'''
def detectionFunc(modelFile, timeSize):
	model = fm.openModel(modelFile)

	list_of_files = glob.glob('live_captures/*.pcapng') # may need changed to .pcap - change path
	latest_file = max(list_of_files, key=os.path.getmtime) # needs to change to getctime on Windows

	current = latest_file

	while True:
		data = rdpcap(current)
		data = dp.timestamps(file, labels, timeSize)

		predictions =  model.predict(data)

		for i in range(len(predictions)):
			if int(predictions[i]) == 1:
				print("anomaly found between " + str((i-1)*timeSize) + ' and  ' + str(i*timeSize))
		
		while latest_file == current:
			list_of_files = glob.glob('/path/to/folder/*.pcapng') # may need changed to .pcap
			latest_file = max(list_of_files, key=os.path.getmtime) # needs to change to getctime on Windows
			time.sleep(5)
			
		current = latest_file

		
	return("Detection Func")


'''
Function for finding best model including data processing
'''
def liveAnalysis(modelFile):
	captureThread = Thread(target=captureFunc(), daemon=True).start()
	detectionThread = Thread(target=lambda: detectionFunc(modelFile), daemon=True).start()
	





# Testing section to ensure functions work correctly
# 	i.e. no missing imports

if __name__ == "__main__":
	openedFile = rdpcap('data/timestamps/training45m.pcapng')
	labels = fm.toList('data/timestamps/training45mClassEDITED.txt') # generate target list
	#training, targets = dp.timestamps(openedFile, labels, 1)
	dp.timestampSize(openedFile, labels)
	#tn, tr, on, opr = fullToLive('data/initial_tests/With_interference_10Hz.pcapng', 'data/initial_tests/With_interference_10HzTARGETS.txt')
	#print(tr)


