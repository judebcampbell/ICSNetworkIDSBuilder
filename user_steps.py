'''
user_steps module 

Contains different functions that combine the other modules into different user story steps
'''

'''
Function
'''
# Removes warning from outputs
def warn(*args, **kwargs):
    pass
import warnings
warnings.warn = warn


import data_processing as dp 
import model_selection as ms 
import model_files as fm

from scapy.all import *

def fullToLive(file, targetFile):
	openedFile = rdpcap(file)
	labels = fm.toList(targetFile) # generate target list
	training, targets = dp.timestamps(openedFile, labels, 5) # transform training data and targets
	model_names, results, pipelines = ms.trainModels(training, targets) #train the initial models
	best_model_names = ms.evaluateModels(results, model_names, 3) # find the 3 best models
	model_names, results, tuned_models = ms.hyperparameterTuning(best_model_names, pipelines, training, targets)
	final_name, final_model = ms.evaluateModels(results, model_names, 1, tuned_models)
	final_name = final_name[0]
	fm.saveBestModel(final_model, final_name, nameFile=False)


if __name__ == "__main__":
	fullToLive('data/initial_tests/CaptureW64.pcapng', 'data/initial_tests/CaptureW64TARGETS.txt')


