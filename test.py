import os

search = 'KNN'

filecomposed = 'model_parameters/' + str(search)  + '.json'
if os.path.isfile(filecomposed):
	print(True)
