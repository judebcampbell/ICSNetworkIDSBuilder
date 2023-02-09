'''
model_files module

contains all functions related to the saving and open necessary saved models for use
'''
import pickle 
from datetime import datetime

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

'''
Function to take file name and read contents into list 
'''
def toList(filename):
	score = []
	with open(filename, "r") as f:
		for line in f:
			score.append(int(line.strip()))
	return(score)