# ICSNetworkIDSBuilder
This code is all the required code needed to run the ICS Intrusion Detection Builder built as part of my 2022-2023 Msci Project at University of Glasgow. 

## Requirements
The specific requirements to run the system are in requirements.txt
Use location requires the following folders:
	1. best_models
	2. figures
	3. live_captures
		a. evaluation

## UI 
UI is run by running the GUI.py file in the command line this is:
```
py GUI.py
```
This will automatically open the GUI (it takes a moment), from this you can input your information and the other files will be called as necessary. 

Outputs will be saved in the figures location - if you want to fave these for future evaluation they must be copied out of this as the graphs are overwritten each time. 

The best model will be saved in the best_models sub directory - with the name of the model and the date. If preprocessing has been identified it will be included in this file but the name will not change. 

## Modules
A brief overview of the modules goals are described below:

### Data Processing 
Contains all functions related to changing input data to feature vectors. File also includes the currently implemented basic preprocessing which considers k-best features and 3 data scaling methods. 

### Model Selection
Contains all functions related to training, optimising and selection models.
If additional models are going to be added to the code the following steps need to be completed:
	1.  a hyper-parameter search grid needs to be created in a JSON format and added to the model_parameters folder.
	2. Appropriate imports are be added to this file
	3. the following line can be added to the generatePipeline() function.
	model name and pipeline name need to match and match the hyper-parameter file name.
```
	pipelines.append(('KNN', (Pipeline([('KNN', KNeighborsClassifier())]))))
```

### Model Files
Model files deals with saving to files and opening files.

### User Steps
Functions combine modules from the previous 4 modules to complete different user requests
