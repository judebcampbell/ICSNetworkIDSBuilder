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
import scikitplot as skplt

import pandas as pd
import matplotlib.colors as mcolors
from mycolorpy import colorlist as mcp


from sklearn.metrics import confusion_matrix
from sklearn.metrics import f1_score, precision_score, recall_score, balanced_accuracy_score

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
	plt.get_legend().remove()
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
	axs.set_xticklabels(names)
	
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
	print('Time bar chart \n')
	evalTimeBarChart(eval_time, names, type)
	print('Eval bar chart')
	lineGraphPlot(recall, names, type, measure='Recall') 
	print('Recall Line')
	boxPlots(bal_acc, names, type, measure='BalancedAccuracy')
	print('Balanced accuracy')
	boxPlots(f1, names, type, measure='f1')
	print('f1 boxplots')
	boxPlots(prec, names, type, measure='Precision')
	print("precission boxplot")
	#boxPlots(recall, names, type, measure='Recall')

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
	return

def confusionMatrixFunc(pred, y, type):
	cm = confusion_matrix(pred, y)
	print(cm.shape)
	if cm.shape == (2,2):
		df_cm = pd.DataFrame(cm, index=['False', 'True'], columns=['False', 'True'])
	else:
		index = list(range(1, cm.shape[0]+1))
		columns = list(range(1, cm.shape[1]+1))
		df_cm = pd.DataFrame(cm, index=index, columns=columns)
	plt.figure(figsize=(7,5))
	sns.heatmap(df_cm, annot=True, cmap='gnuplot2')
	plt.title("Confusion Matrix for best Model")
	save = 'figures/BestMATRIX.png'
	plt.savefig(save)

def ROCCurve(pred, y, type):
	skplt.metrics.plot_roc_curve(y, pred)
	plt.title("ROC cuve for final model")
	save = 'figures/BestROC.png'
	plt.savefig(save)

def PrecRecallCurve(pred, y, type):
	skplt.metrics.plot_precision_recall(y, pred)
	plt.title("ROC cuve for final model")
	save = 'figures/BestPrecRecallCurve.png'
	plt.savefig(save)

def trainTestBar(predTr, trainY, pred, y, type):
	color1=mcp.gen_color(cmap="Set3",n=8)
	
	training, tests = [], []
	metrics = ["Precision", "Recall", "F1", "Balanced Acc"]
	metricFuncs = [precision_score, recall_score, f1_score, balanced_accuracy_score]
	if len(set(y)) > 2:
		for i in range(len(metricFuncs)):
			if metrics[i] == 'Balanced Acc':
				training.append(metricFuncs[i](trainY, predTr))
				tests.append(metricFuncs[i](y, pred))
			else:
				training.append(metricFuncs[i](trainY, predTr, average='weighted'))
				tests.append(metricFuncs[i](y, pred, average='weighted'))
	else:
		for i in range(len(metricFuncs)):
			training.append(metricFuncs[i](trainY, predTr))
			tests.append(metricFuncs[i](y, pred))
	
	bar_width = 0.35
	x_pos = np.arange(len(training))
	fig, ax = plt.subplots()
	bar1 = ax.bar(x_pos, training, bar_width, color=color1[2], label="Training Data")
	bar2 = ax.bar(x_pos + bar_width, tests, bar_width, color=color1[6], label="Test Data")
	ax.bar_label(bar1, fmt='%.2f')
	ax.bar_label(bar2, fmt='%.2f')
	ax.set_xlabel("Metric")
	ax.set_ylabel("Performance")
	ax.set_title("Performance of metrics on Training and Test Data")
	ax.set_xticks(x_pos)
	ax.set_xticklabels(metrics)
	ax.legend()
	fig.tight_layout()
	save = 'figures/BestMetrics.png'
	plt.savefig(save)

def generateUnseenData(models, testX, testY, trainX, trainY, type):
	
	for model in models:
		print(len(testX))
		print(len(testY))

		pred = model.predict(testX)
		print('predict test')
		predTr = model.predict(trainX)
		print('predict train')
		try:
			pred_prob = model.predict_proba(testX)
			print('predict probability test')
		except:
			continue
		confusionMatrixFunc(pred, testY, type)
		print('confusion matrix')
		try:
			ROCCurve(pred_prob, testY, type)
			print('roc curve')
		except:
			print('fail')
		try:
			PrecRecallCurve(pred_prob, testY, type)
			print('Precisoin Recall curve')
		except:
			print('Failed')
		trainTestBar(predTr, trainY, pred, testY, type)
		print('train test bar')




		






