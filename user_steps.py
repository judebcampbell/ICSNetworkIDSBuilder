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


import numpy as np
import pandas as pd

import data_processing as dp 
import model_selection as ms 
import model_files as fm
import graph_production as gp

from scapy.all import *

'''
Function for finding best model including data processing
'''
def fullToLive(file, targetFile):
	openedFile = rdpcap(file)
	labels = fm.toList(targetFile) # generate target list
	training, targets = dp.timestamps(openedFile, labels, 5) # transform training data and targets

	print("\n class balance normal to abnormal in the original data")
	print(gp.class_balance_binary(labels))
	print("\n class balance normal to abnormal in the produced data")
	print(gp.class_balance_binary(targets))
	
	model_names, results, pipelines = ms.trainModels(training, targets) #train the initial models
	best_model_names = ms.evaluateModels(results, model_names, 3) # find the 3 best models
	tuned_model_names, tuned_results, tuned_models = ms.hyperparameterTuning(best_model_names, pipelines, training, targets)
	final_name, final_model = ms.evaluateModels(tuned_results, tuned_model_names, 1, tuned_models)
	final_name = final_name[0]
	fm.saveBestModel(final_model, final_name, nameFile=False)

	gp.recall_boxplot(results, model_names)
	gp.trainTestBarchart(results, model_names)
	return(model_names, results, tuned_model_names, tuned_results)



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

	





# Testing section to ensure functions work correctly
# 	i.e. no missing imports

if __name__ == "__main__":
	tn, tr, on, opr = fullToLive('data/initial_tests/With_interference_10Hz.pcapng', 'data/initial_tests/With_interference_10HzTARGETS.txt')
	print(tr)


