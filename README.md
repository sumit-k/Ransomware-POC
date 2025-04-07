# Ransomware-POC

- Collect the block traces using the eBPF framework 
- Calculate the fetaure set in a sliding window and write it into a  CSV file 
- Upload the CSV to cloud object store 
- Run AutoAI experiment with the CSV assert and download the best trained model 
- Generate new CSVs, reload the model and incrementally train it with new data   
- Continue the process until precision reaches to accepted level

 
SDKs : 
- watson-machine-learning: https://ibm.github.io/watson-machine-learning-sdk/autoai_experiment.html
- watsonx-ai: https://ibm.github.io/watsonx-ai-python-sdk/migration.html

Refs: 
- https://lukasz-cmielowski.medium.com/watson-autoai-can-i-get-the-model-88a0fbae128a
- How to train model outside watson AI:
https://lukasz-cmielowski.medium.com/large-tabular-data-autoai-6876184449dc
https://www.ibm.com/docs/en/watsonx/saas?topic=learning-saving-autoai-generated-notebook

- Client details: 
https://lukasz-cmielowski.medium.com/peaking-behind-the-curtain-with-ibm-watson-autoai-python-client-3062836c048
