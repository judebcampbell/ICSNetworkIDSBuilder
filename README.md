# ICSNetworkIDSBuilder
This code is all the required code needed to run the ICS Intrusion Detection Builder built as part of my 2022-2023 Msci Project at University of Glasgow. 

## Requirements
The specific requirements to run the system are in requirements.txt
Use location requires the following folders:
	1. best_models
	2. figures
	3. live_captures
		a. evaluation
## Assumptions
The system assumes that the data files used are either directly in line from the current folder or in a subfolder. It uses full relative addresses. 

## UI 
UI is run by running the GUI.py file in the command line this is:
```
py GUI.py
```
This will automatically open the GUI (it takes a moment), from this you can input your information and the other files will be called as necessary. 

Outputs will be saved in the figures location - if you want to fave these for future evaluation they must be copied out of this as the graphs are overwritten each time. 

**The GUI for live detection is unfinished. I have not successfully been able to connect the output box to the updating output. This should not be hard to correct but it currently runs without issue but the GUI freezers. Because the function never updates. 
**

The best model will be saved in the best_models sub directory - with the name of the model and the date. If preprocessing has been identified it will be included in this file but the name will not change. 

## Modules
A brief overview of the modules goals are described below:

### Data Processing 
Contains all functions related to changing input data to feature vectors. File also includes the currently implemented basic preprocessing which considers k-best features and 3 data scaling methods. 

Not discussed in the Paper is the use preprocessing which has been implemented minimally. The system will automatically trial the preprocessing on the best initial model. It will attempt to find the K best feature, where 5 < K < no of input features. It will also attempt to compare performance of the raw data to some scaling methods: Standard Scaler, Min Max Abs Scaler and Robust Scaler.

When used; if a best preprocessing is identified then the system will automatically preprocess the data is has and add the the preprocessing to the saved best model to create a saved best pipeline. 

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
Functions combine modules from the previous 4 modules to complete different user requests. This includes 3 functions that can be called. One for seperated data and labels where data is a .csv. One for seperated data and labels that will include preprocessing from .pcap to df, and the last one is for integrated .csv data and labels. 

Both the functions for .csv data include adaptation of columns to ml appropriate columns and the automatic dropping of rows with inifinity and NAN values. This should likely be abstracted out into a seperate function.

This module also includes the 3 live detection functions. One for data capturing, one for data prediction and a leader function to create the threads. In the Data Capture function the following line needs to be updated to be the correct network stream. **_find code and add value_**
