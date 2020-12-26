# virustotal-vt3
<i>files_to_upload</i> is the folder where the files are stored to check with Virustotal.

<i>output_json</i> is the folder where all the json files will be stored. <br>
The naming convention of the output files is the hash of the original file with .json. If the hash of the file you want to check is <b>aaa</b>,  the json filename would be <b>aaa.json</b>

<i>vt_start_trigger.sh</i> is the shell code which checks all the files in <i>files_to_upload</i> folder with using Virustotal API and then waits for any new file to be added and as soon as a new file is added to the folder, it checks it with Virustotal and generates the reuslt in a json file in <i>output_json</i> folder.

<i>vt_upload_cmd_line.py</i> is the code which checks a file with virustotal from the file path given in command line.<br>
To use it independently, run it like:<br>
<t><b>python3 vt_upload_cmd_line.py /path/to/file/file.exe</b><br>
The output json is stored in <i>output_json</i> folder.

<i>vt_upload_folder.py</i> is the code which checks a whole folder and generates json output.<br>
To modify, change the path of the folder you want to check in the directory variable of the <i>get_files_from_folder()</i> function.

Python Library Requirements:
The libraries used to develop this software are available while you install python3 and pip3. Only the <i>requests</i> library is the one which has to be explicitly installed.
<b><i>pip3 install requests</b></i>
