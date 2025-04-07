import wget
import os

filename="electricity.csv"

url = "https://github.com/IBM/watson-machine-learning-samples/raw/master/cloud/data/electricity/electricity.csv"
if not os.path.isfile(filename): 
    wget.download(url)
