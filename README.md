# Ransomware-POC

- Collect the block traces using the eBPF framework 
- Calculate the fetaure set in a sliding window and write it into a  CSV file 
- Upload the CSV to cloud object store 
- Run AutoAI experiment with the CSV assert and download the best trained model 
- Generate new CSVs, reload the model and incrementally train it with new data   
- Continue the process until precision reaches to accepted level


