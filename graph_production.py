'''
Graph Production Module

Contains all functions for:
	- sorting data produced during training/optimisation
	- generating and saving plots
	- provide statistics about labels
'''
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

import pandas as pd
import matplotlib.colors as mcolors

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

def seperatedBarChart(fit_times, model_names, name):
	ordered = []

	for i in range(len(fit_times[0])):
		row = []
		for j in range(len(fit_times)):
			row.append(fit_times[j][i])
		ordered.append(row)
	
	columns = []
	for i in range(len(model_names)):
		columns.append(model_names[i])
	df =  pd.DataFrame(ordered, columns=columns)

	df.plot(kind='bar', colormap='Set3', subplots=True, figsize=(5,6))
	plt.tight_layout()
	plt.xlabel("Training split")
	plt.ylabel("Time in Seconds")
	plt.title("Training time for each model across splits")

	saveTitle = 'figures/' + str(name) + "TimeSeperateBars.png"
	plt.savefig(saveTitle)
  
def evalTimeBarChart(eval_time, model_names, name):
	ordered = []

	for i in range(len(eval_time[0])):
		row = []
		for j in range(len(eval_time)):
			row.append(eval_time[j][i])
		ordered.append(row)

	columns = []
	for i in range(len(model_names)):
		columns.append(model_names[i])
	df =  pd.DataFrame(ordered, columns=columns)

	df.plot(kind='bar', stacked=True, colormap='Set3')# subplots=True, legend=True, figsize=(5,5))
	plt.xlabel("split")
	plt.ylabel("Time in Seconds")
	plt.title("Evaluation time for test data in each split")

	saveTitle = 'figures/' + str(name) + "EvalTimeStackedBars.png"
	plt.savefig(saveTitle)

def lineGraphPlot(results, names, type, measure):
	ordered = []

	for i in range(len(results[0])):
		row = []
		for j in range(len(results)):
			row.append(results[j][i])
		ordered.append(row)

	columns = []
	for i in range(len(names)):
		columns.append(names[i])

	df =  pd.DataFrame(ordered, columns=columns)

	df.plot(colormap='Set3')
	#plt.plot(df, colormap='Tab3')
	plt.title(measure + ' across ' + type + ' splits')
	plt.ylabel(measure)
	plt.xlabel('splits')

	saveTitle = 'figures/' + str(type) + measure + 'LineGraph.png'
	plt.savefig(saveTitle)

def boxPlots(results, names, type='Training', measure='Precision'):
	ordered = []

	for i in range(len(results[0])):
		row = []
		for j in range(len(results)):
			row.append(results[j][i])
		ordered.append(row)

	columns = []
	for i in range(len(names)):
		columns.append(names[i])

	df =  pd.DataFrame(ordered, columns=columns)

	boxprops = dict(linestyle='-', linewidth=1, color='#F5CFE4', facecolor= '#F5CFE4')
	whiskerprops = {"color": '#B484B9', "linewidth": 2, "linestyle": '--'}
	capprops={"color": 'k',  "linewidth": 1.5}
	medianprops = {"color": "#B484B9", "linewidth": 3}
	meanprops = dict(marker='D', markeredgecolor='black',  markerfacecolor='#9DD1C7')

	fig, axs = plt.subplots(1)
	plt.title(measure + " across training splits")
	axs.boxplot(df,patch_artist=True,boxprops = boxprops, whiskerprops=whiskerprops, capprops=capprops,  medianprops=medianprops, meanprops=meanprops, showmeans=True)
	axs.set_xticklabels(names, rotation=45)
	
	saveTitle = 'figures/' + str(type) + measure + "BoxPlots.png"
	plt.savefig(saveTitle)

def generatePlots(results, names, type='Training'):
	fits = []
	eval_time = []
	bal_acc = []
	f1 = []
	prec = []
	recall = []

	for i in range(len(results)):
		fits.append(results[i]['fit_time'])
		eval_time.append(results[i]['score_time'])
		bal_acc.append(results[i]['test_balanced_accuracy'])
		f1.append(results[i]['test_f1'])
		prec.append(results[i]['test_precision'])
		recall.append(results[i]['test_recall'])
	
	seperatedBarChart(fits, names, type)
	evalTimeBarChart(eval_time, names, type)
	lineGraphPlot(recall, names, type, measure='Recall')
	boxPlots(bal_acc, names, type, measure='BalancedAccuracy')
	boxPlots(f1, names, type, measure='f1')
	boxPlots(prec, names, type, measure='Precision')
	boxPlots(recall, names, type, measure='Recall')

def generatePlotsReduced(results, names, type='Training'):
	fits = []
	eval_time = []
	bal_acc = []
	f1 = []
	prec = []
	recall = []

	for i in range(len(results)):
		fits.append(results[i]['fit_time'])
		eval_time.append(results[i]['score_time'])
		bal_acc.append(results[i]['test_balanced_accuracy'])
		f1.append(results[i]['test_f1'])
		prec.append(results[i]['test_precision'])
		recall.append(results[i]['test_recall'])
	

	#lineGraphPlot(recall, names, type, measure='Recall')
	boxPlots(bal_acc, names, type, measure='BalancedAccuracy')
	boxPlots(f1, names, type, measure='f1')
	#boxPlots(prec, names, type, measure='Precision')

