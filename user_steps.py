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
from glob import glob
import json

import numpy as np
import pandas as pd

import data_processing as dp 
import model_selection as ms 
import model_files as fm
import graph_production as gp
from numpy import savetxt

from scapy.all import *
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler
from threading import Thread
import time 
from sklearn.pipeline import make_pipeline

'''
Function for finding best model including data processing
'''
def fullToLive(file, targetFile):
	start = time.time()
	f =  open(('figures/outputText.txt'), "w")
	openedFile = rdpcap(file)
	labels = fm.toList(targetFile) # generate target list
	training, targets, freq = dp.timestamps(openedFile, labels) # transform training data and targets

	print(training.head(10))
	#training.to_csv('data/timestamps/52minuteTIMESTAMPS.csv')
	
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

	model_names, results, pipelines = ms.trainModels(trainX, trainY) #train the initial models
	best_model_names = ms.evaluateModels(results, model_names, 3) # find the 3 best models
	x, reduc, scaler =  dp.preprocessData(training, targets, pipelines, best_model_names[-1:])

	trainX = x[:split]
	testX = x[split:]
	print('Best Preprocessing Found')

	tuned_model_names, tuned_results, tuned_models = ms.hyperparameterTuning(best_model_names, pipelines, trainX, trainY)
	final_name, final_model = ms.evaluateModels(tuned_results, tuned_model_names, 1, tuned_models)
	print(final_name)
	final_name = final_name[0]
	if reduc != None or scaler != None:
		pipe = fm.planPipeline(final_model, reduc, scaler)
		fm.saveBestModel(pipe, final_name, nameFile=False)
	else:
		fm.saveBestModel(final_model, final_name, nameFile=False)


	gp.generatePlots(results, model_names, "Training")
	gp.generatePlots(tuned_results, tuned_model_names, "Optimised")
	gp.generateUnseenData(final_model, testX, testY, trainX, trainY, 'Best')

	end = time.time() - start
	f.write("Time taken to process = " + str(end))
	f.write("\nBest model found was: " + str(final_name))
	f.write("\nTraining data size:   " + str(split) + "\n")
	f.write("Test data size:   " + str(val - split) + "\n")
	f.write("Feature vectors calculated every  " + str(freq) + '  seconds' + "\n")
	f.write("Class imbalance:" + "\n")
	f.write("	Normal:  " + str(n) + "\n")
	f.write("	Abnormal:  " + str(a) + "\n")
	f.close()

	print(results)
	print('\n \n \n \n')
	print(tuned_model_names)
	print('\n \n')
	print(tuned_results)
	return(model_names, results, tuned_model_names, tuned_results, freq)

'''
Function to find best model for data that does not need to be processed in the system
'''
def modelSelectionNoProcessing(file, targets):
	start = time.time()
	f =  open(('figures/outputText.txt'), "w")
	targets = fm.toList(targets) # generate target list
	training = pd.read_csv(file)
	print(len(training))
	print(len(targets))


	print(training.dtypes)
	to_del = []
	for column in training:
		if training[column].dtypes == 'object':
			col_id = str(column) + '_id'
			training[col_id], x = pd.factorize(training[column])
			to_del.append(column)

	training =  training.drop(to_del, axis=1)
	training = training.reset_index()
	training['label'] = targets
	training = training.replace((np.inf, -np.inf, np.nan), 0).reset_index(drop=True)
	training = training.loc[:,training.apply(pd.Series.nunique) != 1]
	training = training.dropna()
	targets = training['label']
	training =  training.drop('label', axis=1)
	training = training.reset_index()
	print(training.head(5))
	val = len(training)
	split = round(0.4 * len(training))
	trainX = training[:split]
	trainY = targets[:split]
	testX = training[split:]
	testY = targets[split:]

	print("\n class balance normal to abnormal in the produced data")
	n, a =gp.class_balance_binary(trainY)
	print(n, a)

	model_names, results, pipelines = ms.trainModels(trainX, trainY) #train the initial model
	best_model_names = ms.evaluateModels(results, model_names, 3) # find the 3 best models
	print(best_model_names[-1:])
	x, reduc, scaler =  dp.preprocessData(training, targets, pipelines, best_model_names[-1:])

	trainX = x[:split]
	testX = x[split:]
	print('Best Preprocessing Found')

	tuned_model_names, tuned_results, tuned_models = ms.hyperparameterTuning(best_model_names, pipelines, trainX, trainY)
	print('Models Tuned')
	final_name, final_model = ms.evaluateModels(tuned_results, tuned_model_names, 1, tuned_models)
	print('Best Model found')
	final_name = final_name[0]
	if reduc != None or scaler != None:
		pipe = fm.planPipeline(final_model, reduc, scaler)
		fm.saveBestModel(pipe, final_name, nameFile=False)
	else:
		fm.saveBestModel(final_model, final_name, nameFile=False)
	print('Model Saved')
	gp.generatePlots(results, model_names, "Training")
	gp.generatePlots(tuned_results, tuned_model_names, "Optimised")
	gp.generateUnseenData(final_model, testX, testY, trainX, trainY, 'Best')
	print("Plots Generated")

	end = time.time() - start
	f.write("Time taken to process = " + str(end))
	f.write("\nBest model found was: " + str(final_name))
	f.write("\nTraining data size:   " + str(split) + "\n")
	f.write("Test data size:   " + str(val - split) + "\n")
	#f.write("Feature vectors calculated every  " + str(freq) + '  seconds' + "\n")
	f.write("Class imbalance:" + "\n")
	f.write("	Normal:  " + str(n) + "\n")
	f.write("	Abnormal:  " + str(a) + "\n")
	f.close()

	print(results)
	print('\n \n \n \n')
	print(tuned_model_names)
	print('\n \n')
	print(tuned_results)
	return(model_names, results, tuned_model_names, tuned_results)

def modelSelection1File(file):
	start = time.time()
	print('opening outputfile')
	f =  open(('figures/outputText.txt'), "w")
	print('opening file')
	print(file)
	training = pd.read_csv(file)
	print('Read Training file')
	print(training.head(5))
	#training =  training.iloc[:1000000]
	labels, c = pd.factorize(training['label'])
	labels = labels.tolist()
	print(len(set(labels)))
	print('Extracted targets')

	training = training.drop(['label'], axis=1)
	
	training, targets = dp.electraTimestamps(training, labels)
	print('Data ready')
	print(training.head(5))
	print(targets)


	val = len(training)
	split = round(0.1 * len(training))
	trainX = training[:split]
	trainY = targets[:split]
	testX = training[split:]
	testY = targets[split:]
	print("Data split for training and testing. ")

	print("\n class balance normal to abnormal in the produced data")
	n, a =gp.class_balance_binary(targets)
	print(n, a)

	model_names, results, pipelines = ms.trainModels(trainX, trainY) #train the initial models
	print('initial evaluation')
	best_model_names = ms.evaluateModels(results, model_names, 3) # find the 3 best models
	print("initial best models found")
	x, reduc, scaler =  dp.preprocessData(training, targets, pipelines, best_model_names[-1:])
	trainX = x[:split]
	testX = x[split:]
	print("Best Preprocessing found")

	tuned_model_names, tuned_results, tuned_models = ms.hyperparameterTuning(best_model_names, pipelines, trainX, trainY)
	print("models tuned")
	final_name, final_model = ms.evaluateModels(tuned_results, tuned_model_names, 1, tuned_models)
	print("Best model found")
	print(final_name)
	final_name = final_name[0]
	if reduc != None or scaler != None:
		pipe = fm.planPipeline(final_model, reduc, scaler)
		print("pipeline constructed")
		fm.saveBestModel(pipe, final_name, nameFile=False)
	else:
		fm.saveBestModel(final_model, final_name, nameFile=False)
	print('best model saved')

	gp.generatePlots(results, model_names, "Training")
	gp.generatePlots(tuned_results, tuned_model_names, "Optimised")
	gp.generateUnseenData(final_model, testX, testY, trainX, trainY, 'Best')
	print("plots generated")

	end = time.time() - start
	print("writing stats to file")
	f.write("Time taken to process = " + str(end))
	f.write("\nBest model found was: " + str(final_name))
	f.write("\nTraining data size:   " + str(split) + "\n")
	f.write("Test data size:   " + str(val-split) + "\n")
	#f.write("Feature vectors calculated every  " + str(freq) + '  seconds' + "\n")
	f.write("Class imbalance:" + "\n")
	f.write("	Normal:  " + str(n) + "\n")
	f.write("	Abnormal:  " + str(a) + "\n")
	f.close()

	print(results)
	print('\n \n \n \n')
	print(tuned_model_names)
	print('\n \n')
	print(tuned_results)
	return(model_names, results, tuned_model_names, tuned_results)
'''
Function for live continous data captures on the relevant testbed
'''
def captureFunc():
	os.system(r'C:\>"Program Files"\Wireshark\tshark -i "\Device\NPF_{1816C53A-67EF-4559-828E-6844F599F1D6}" -b duration:100 -b files:10 -w H:\ICSNetworkIDSBuilder-main\live_captures\file.pcapng')
	return("Capture Func")
	

'''
Function for predicting attacks and alerting user
'''
def detectionFunc(modelFile, timeSize):
	f =  open(('live_captures/anomalyTimes.txt'), "w")
	print("opening Models")
	model = fm.openModel(modelFile)

	time.sleep(300)

	list_of_files = glob('live_captures/*.pcapng') # may need changed to .pcap - change path
	latest_file = max(list_of_files, key=os.path.getctime) # needs to change to getctime on Windows

	current = latest_file
	counter = 1

	while True:
		d = rdpcap(current)
		data = dp.timestamps(d,  size=int(timeSize))

		predictions =  model.predict(data)

		for i in range(len(predictions)):
			if int(predictions[i]) == 1:
				line = "anomaly found between " + str((i)*timeSize) + ' and  ' + str(i+1*timeSize)
				print(line) 
				f.write(line)
		
		f.write('If any anomalies have been detected above ')
		if 1 in predictions:
			outfile = str(counter) + 'Anomaly.pcap'
			f.write('Abova anomalies can be viewed in file ' + outfile)
			wrpcap(outfile, d)
			counter += 1
		
		f.write("\n \n")

		while latest_file == current:
			list_of_files = glob('live_captures/*.pcapng') # may need changed to .pcap
			latest_file = max(list_of_files, key=os.path.getctime) # needs to change to getctime on Windows
			time.sleep(50)
			
		current = latest_file

		
	return("Detection Func")


'''
Function for finding best model including data processing
'''
def liveAnalysis(modelFile, freq=5):
	print(modelFile)
	captureThread = Thread(target=captureFunc(), daemon=True).start()
	detectionThread = Thread(target=lambda: detectionFunc(modelFile, freq), daemon=True).start()
	





# Testing section to ensure functions work correctly
# 	i.e. no missing imports

if __name__ == "__main__":
	#openedFile = rdpcap('data/timestamps/training45m.pcapng')
	#labels = fm.toList('data/timestamps/training45mClassEDITED.txt') # generate target list
	#training, targets = dp.timestamps(openedFile, labels, 1)
	#dp.timestampSize(openedFile, labels)
	#tn, tr, on, opr, freq = modelSelectionNoProcessing('data/evaluation/WADI_attackdata.csv', 'data/evaluation/WADI_attackdataClass.txt')
	#print(tr)
	#liveAnalysis(modelFile=
	pass
