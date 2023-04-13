'''
IDS Builder 
April 2023
Jude Campbell - 2382182c

model_files module
	contains all functions related to the saving and open 
	necessary saved models for use.
'''
import pickle 
from datetime import datetime
from sklearn.pipeline import make_pipeline

'''
Function saves best model for use at a later date
inputs: 
	model - model to be saved
	modelName - name of the model (default = 'finalModel')
	nameFile - if True, user can input file name
'''
def saveBestModel(model, modelName='FinalModel', nameFile = False):

	if nameFile == False:
		filename = str(modelName) + datetime.today().strftime('%Y-%m-%d') + '.sav'
	else:
		filename = input("Enter Model name: ")
		filename = filename + '.sav'

	filename = 'best_models/' + filename
	pickle.dump(model, open(filename, 'wb'))
	#print("\nModel Saved as: " + filename)

def planPipeline(model, columndrops, scaler):
	if scaler == None:
		pipe = make_pipeline(columndrops, model)
	if columndrops == None:
		pipe = make_pipeline(scaler, model)
	else:
		pipe = make_pipeline(columndrops, scaler, model)
	print(pipe)
	return(pipe)

def openModel(filename):
	return(pickle.load(open(filename, 'rb')))

'''
Function to take file name and read contents into list 
'''
def toList(filename):
	score = []
	with open(filename, "r") as fil:
		for line in fil:
			score.append(int(line.strip()))
	return(score)