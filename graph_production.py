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

'''\[
{
	'fit_time': array(\[0.08850408, 0.09285307, 0.10435987, 0.09361601, 0.08934808]), 
	'score_time':  array(\[0.00908804, 0.00974202, 0.01023912, 0.009588  , 0.00903511]), 
	'test_balanced_accuracy': array(\[1.  , 1.  , 0.95, 1.  , 0.5 ]), 
	'test_f1': array(\[1.        , 1.        , 0.94736842, 1.        , 0.91891892]),
	'test_precision': array(\[1.  , 1.  , 1.  , 1.  , 0.85]), 
	'test_recall': array(\[1. , 1. , 0.9, 1. , 1. ])},
{
	'fit_time': array(\[0.002177  , 0.00199604, 0.00209689, 0.00202179, 0.00206089]), 
	'score_time': array([0.00310135, 0.00278878, 0.00287008, 0.00317121, 0.00281882]), 
	'test_balanced_accuracy': array([1. , 1. , 0.5, 1. , 0.5]),
	 'test_f1': array([1.        , 1.        , 0.97560976, 1.        , 0.91891892]), 
	 'test_precision': array([1.        , 1.        , 0.95238095, 1.        , 0.85      ]), 
	 'test_recall': array([1., 1., 1., 1., 1.])}, 
{
	'fit_time': array([0.00220227, 0.00196981, 0.00196505, 0.00209785, 0.00198412]),
	'score_time': array([0.00289989, 0.00302696, 0.00279808, 0.00291395, 0.00313091]), 
	'test_balanced_accuracy': array([1.        , 1.        , 0.5       , 0.95238095, 0.5       ]),
	'test_f1': array([1.        , 1.        , 0.97560976, 0.97560976, 0.91891892]), 
	'test_precision': array([1.        , 1.        , 0.95238095, 1.        , 0.85      ]), 
	'test_recall': array([1.        , 1.        , 1.        , 0.95238095, 1.        ])},
{
	'fit_time': array([0.00195503, 0.00200701, 0.001863  , 0.00199604, 0.001966  ]), 
	'score_time': array([0.00279903, 0.00279808, 0.00297999, 0.00283003, 0.00286007]), 
	'test_balanced_accuracy': array([1.  , 1.  , 0.95, 1.  , 0.5 ]), 
	'test_f1': array([1.        , 1.        , 0.94736842, 1.        , 0.91891892]), 
	'test_precision': array([1.  , 1.  , 1.  , 1.  , 0.85]), 
	'test_recall': array([1. , 1. , 0.9, 1. , 1. ])}, 
{
	'fit_time': array([0.00198388, 0.00191998, 0.00193   , 0.0019002 , 0.00184774]), 
	'score_time': array([0.00383902, 0.00375867, 0.003654  , 0.00366378, 0.0040319 ]), 
	'test_balanced_accuracy': array([1. , 1. , 0.5, 1. , 0.5]), 
	'test_f1': array([1.        , 1.        , 0.97560976, 1.        , 0.91891892]), 
	'test_precision': array([1.        , 1.        , 0.95238095, 1.        , 0.85      ]), 
	'test_recall': array([1., 1., 1., 1., 1.])}, 
{
	'fit_time': array([0.00207615, 0.00207806, 0.00187016, 0.00192904, 0.00208497]),
	'score_time': array([0.0028708 , 0.00284481, 0.00294805, 0.00282216, 0.00281906]), 
	'test_balanced_accuracy': array([1. , 1. , 0.5, 1. , 0.5]), 
	'test_f1': array([1.        , 1.        , 0.97560976, 1.        , 0.91891892]), 
	'test_precision': array([1.        , 1.        , 0.95238095, 1.        , 0.85      ]), 
	'test_recall': array([1., 1., 1., 1., 1.])}]'''
def time_boxplot(results, model_name):
	trainingTimes = []
	fitTimes = []
	for i in range(len(results)):
		trainingTimes.append(results[i]['fit_time'])
		fitTimes.append(results[i]['score_time'])

	fig, axs = plt.subplots(2)
	fig.suptitle('Training Time and scoring time for each CV')
	axs[0].boxplot(trainingTimes,patch_artist=True,boxprops = dict(linestyle='-', linewidth=1, color='tab:pink', facecolor= 'tab:pink'), whiskerprops={"color": 'k', "linewidth": 1.5}, capprops={"color": 'k',  "linewidth": 1.5},  medianprops={"color": "k", "linewidth": 1})
	axs[1].boxplot(fitTimes, patch_artist=True,boxprops = dict(linestyle='-', linewidth=1, color='tab:pink', facecolor= 'tab:pink'), whiskerprops={"color": 'k', "linewidth": 1.5}, capprops={"color": 'k',  "linewidth": 1.5},  medianprops={"color": "k", "linewidth": 1})
	axs[0].set_xticklabels([])
	axs[0].set_xticks([])
	axs[1].set_xticklabels(model_name)
	plt.savefig("figures/" + "boxplotsTimes")
	plt.show()

def recall_boxplot(results, model_name):
	trainingTimes = []
	fitTimes = []
	for i in range(len(results)):
		trainingTimes.append(results[i]['test_recall'])

	fig, axs = plt.subplots(1)
	fig.suptitle('Recall for each model')
	axs.boxplot(trainingTimes,patch_artist=True,boxprops = dict(linestyle='-', linewidth=1, color='tab:pink', facecolor= 'tab:pink'), whiskerprops={"color": 'k', "linewidth": 1.5}, capprops={"color": 'k',  "linewidth": 1.5},  medianprops={"color": "k", "linewidth": 1})
	#axs[1].boxplot(fitTimes, patch_artist=True,boxprops = dict(linestyle='-', linewidth=1, color='tab:pink', facecolor= 'tab:pink'), whiskerprops={"color": 'k', "linewidth": 1.5}, capprops={"color": 'k',  "linewidth": 1.5},  medianprops={"color": "k", "linewidth": 1})
	axs.set_xticklabels(model_name)
	axs.set_xticks([])
	#axs[1].set_xticklabels(model_name)
	plt.savefig("figures/" + "boxplotsRecall")

def trainTestBarchart(results, model_name):
	colours = ['deeppink', 'darkorchid', 'rebeccapurple', 'royalblue', 'slategray']
	N = len(results)
	training = []
	test = []
	width = 0.25

	ind = np.arange(N-1)
	for i in range(N):
		training.append(results[i]['fit_time'])
		test.append(results[i]['score_time'])
	bar1 = plt.bar(ind, training[0], width, color = colours[0])
	bar2 = plt.bar(ind+width, training[1],width,  color = colours[1])
	bar3 = plt.bar(ind+(width*2), training[2],width, color = colours[2])
	bar4 = plt.bar(ind+(width*3), training[3],width, color =  colours[3])
	bar5 = plt.bar(ind+(width*4), training[4],width, color = colours[4])

	plt.xlabel("Fold")
	plt.ylabel("time")
	plt.title("Model training time across folds")

	plt.xticks(ind+(width*2),[1, 2, 3, 4, 5] )
	plt.legend( (bar1, bar2, bar3, bar4, bar5), model_name )
	plt.savefig("figures/" + "barchartsTrainingTime")



  
