#!/usr/bin/python3
# If you are using Python < 2.5, you need to install hashlib. pip install hashlib

import requests
import json
import hashlib
import os
import sys
"""
In Virustotal VT3 API, when a new file is uploaded, it generates an ID for the same. You can check the result after the analysis is completed with the same ID. It usually takes some time to
analyze the file and generate result. That's why there is a sleep of 120 seconds in the check_id_of_uploaded_file function. The more the size of the file(max can be 32 MB for Public API), the
more time you have to make it sleep
"""

#Put the Virustotal API Key in the header
headers = {'x-apikey': '<API KEY'}

#Function to check the ID of the file that has been uploaded
def check_id_of_uploaded_file(id_of_file,hash_of_file):
	os.system("sleep 300")
	
	#URL of the file concat with the ID
	url_get_file = 'https://www.virustotal.com/api/v3/analyses/'+id_of_file

	#get request to get the result from virustotal and convert it into json
	response_file_upload_virustotal = requests.get(url_get_file, headers=headers).json()
	
	#Beautifying the JSON.
	print(json.dumps(response_file_upload_virustotal, sort_keys=False, indent=4))
	
	#Writing the json to a file name by the hash of the original file
	with open("/output_json/"+hash_of_file+".json", "w") as outfile:
		json.dump(response_file_upload_virustotal, outfile, indent=4)
	#Any operation can be done on the JSON that has been stored in response_file_upload_virustotal variable. You can find an example in the catch part of check_hash_virustotal function
	
#Function to uplaod the file in virustotal
def upload_file_virustotal(current_file,hash_of_file):
	print("It seems the file is not in Virustotal database. Uploading the file to Virustotal...")
	
	#URL to upload the file to Virustotal -- Given in Virustotal Website
	url = 'https://www.virustotal.com/api/v3/files'
	
	#Reading the file
	files = {'file': (current_file, open(current_file, 'rb'))}
	
	#Getting the response from Virustotal and converting it into JSON
	response_file_upload_id_virustotal = requests.post(url, headers=headers, files=files).json()
	
	#Extracting the ID of the uploaded file that has been queued
	id_received = response_file_upload_id_virustotal["data"]["id"]
	print(id_received)
	print("Checking ID of the file received")
	
	#Calling this function to check the results
	check_id_of_uploaded_file(id_received,hash_of_file)
	#os.system("sleep 20")
	
	
#Function to check MD5 hash of the with Virustotal Database. If there is any match, it will give the results	
def check_hash_virustotal(current_file):

	#Opening the file
	with open(current_file, "rb") as f:
	
		#Generating the hash of the file
		malware_md5 = hashlib.md5(f.read()).hexdigest()
		
		#Virustotal V3 URL to compare the hash of the file with Virustotal Database
		url = 'https://www.virustotal.com/api/v3/files/'+malware_md5
		
		#Getting the response from Virustotal and converting it into JSON
		response_hash_virustotal = requests.get(url, headers=headers).json()
		
		
		#Beautifying JSON
		print("RESULTS FOR FILE IN PATH: \n %s"%(current_file))
		print(json.dumps(response_hash_virustotal, sort_keys=False, indent=4))
		print("\n \n \n \n")
		
		#To view the whole JSON, just print the response_hash_virustotal variable
		#There can be two cases here. Either the file will be there and the code will go to the try part. If not, there will be an exception and the code will go to the except part and upload the file to Virustotal
		try:	
			#Writing the json to a file name by the hash of the original file
			with open("/output_json/"+malware_md5+".json", "w") as outfile:
				json.dump(response_hash_virustotal, outfile, indent=4)
			#This variable stores the last_analysis_results field which has all the results from the Antivirus softwares that virustotal uses	
			last_analysis_results= response_hash_virustotal["data"]["attributes"]["last_analysis_results"]
			#print(last_analysis_results)

			#Iterating through all the items inside the last_analysis_result variable(which is a JSON) and printing only the ones which shows malicious
			for (antivirus,results) in last_analysis_results.items():
				#print("Antivirus: "+antivirus)
				#print("Result: "+ str(results)) -- This and the previous line can print all the Results
				category = results["category"]
				if (category == "malicious"):
					print("Antivirus: "+ antivirus)
					print("RESULTS: "+str(results))
					print("\n \n \n")
		except:
			check_error_or_not = response_hash_virustotal["error"]["code"]
			print(check_error_or_not)
			if check_error_or_not == "NotFoundError":
				upload_file_virustotal(current_file,malware_md5)
		
#function to iterate over the given folder and upload all the files to check with Virustotal
def get_files_from_folder():
	directory="/files_to_upload"
	for filename in os.listdir(directory):
		current_file = os.path.join(directory, filename)
		#print(current_file)
		check_hash_virustotal(current_file)

if __name__ == "__main__":
	get_files_from_folder()
