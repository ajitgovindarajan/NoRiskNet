\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*

* Name      : Ajit Govindarajan
* Student ID: 107861904
* Class     :  CSCI 5742 Section 01
* Final Project
* Due Date  :  May. 02, 2023

\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*


Read Me: Network Risk Assessment Forum: NoRiskNet


\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*

* Description of the program

\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*

1.  The program will scan all the IP address within the present network that is taken by the enterprise
2. The IP addresses will be taken by wither inputted CIDR notation, default range, or the assigned starting address
and ending address by the user
3. Within the IP addresses, the 1024 ports will also be scanned within the check. Also, an option will be given to 
the user to scan what ever ports that are requested or default to 1024 based the choice made by the user
4. Those port scans will include the TCP, UDP and ICMP ports scanning to see which ports are open which will show which
ports are open and will factor into the security of the network and what information is being accessed in a certain port
5. With all of that information, the program will refer to the CVE repository to check based on the given criteria
the relative security of the network through a different address 
6. Once those metrics have been accumulated, the relative score based on the CVSS scoring will be done in different
function 
7. the relative CVSS score that will be used as the scoring criteria of the security to assess whether the domain is safe 
8. Once the security report has been written up, then we can add some possible solutions that can be used to make the network
safer


\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*

* Source files

\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*

Name:  main.py

Main program.  This file contains the whole network risk assessment program. The file contains the functions that will
find the IP addresses that will be scanned through port scanners. The port scanners will take a users input of what ports
are to be scanned and will be UDP, TCP and ICMP scanned. The open ports will then be appended to the lists which will 
then be taken into account for the metrics calculations. That will conclude the scanning portion of the program. The 
next part of the program is about retrieving the data from the CVE repository in order to send to the CVSS calculator. 
The program will then take the full metrics from the cve database with that calculate the CVSS score of each of the 
networks. The comprehensive report will be printed out and then based on the report potential fixes can be found
for the network that is scanned.

requirements.txt

These requirements.txt file provides the required libraries that need to be installed for this program to be run without
any compatibility issue nd make sure of any errors, then it is repository or coding errors


\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*

* Sources/Bibliography

\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*
https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?name=CVE-2016-0051
https: // developer.mozilla.org / en - US / docs / Web / HTTP / Status  # successful_responses
https://nvd.nist.gov/Vulnerability-Metrics/Calculator-Product-Integration
https://docs.python.org/3/library/ipaddress.html
https://stackoverflow.com/questions/60178826/extracting-cve-info-with-a-python-3-regular-expression

https://www.w3schools.com/python/python_lambda.asp

https://www.geeksforgeeks.org/python-sorted-function/#

https://devconnected.com/how-to-ping-specific-port-number/

https://stackoverflow.com/questions/20621485/how-can-i-seperate-ips-when-written-to-a-file

https://pypi.org/project/nvdlib/

https://www.programcreek.com/python/example/69299/subprocess.getstatusoutput

Source for the requirements txt 
https://stackoverflow.com/questions/7225900/how-can-i-install-packages-using-pip-according-to-the-requirements-txt-file-from

Mell, P. , Kent, K. and Romanosky, S. (2006), Common Vulnerability Scoring System, IEEE Security & Privacy, 
[online], https://tsapps.nist.gov/publication/get_pdf.cfm?pub_id=50899 (Accessed May 1, 2023)

Portscanner code was produced from the outline provided by the professor of this class: Dr. J Haadi Jafarian and 
the Teaching Assistant: Chase Brown

\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*

* Circumstances of programs

\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*

The program runs successfully.

The program was developed and tested on Kali Linux version 2022.  It was

compiled, run, and tested on Kali Linux server. Provided by Dr.Haadi

Jafarian. 

The program also runs successfully runs on the Windows system with the installation

of the requests library, json library, socket library, ipaddress library, and the subprocess library

create a file that will run all the python imports

Python version: 3.10.2

Kali Linux Version : 2022 or 2023
\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*

* How to build and run the program

\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*

1. Uncompress the Project file.  The project file is compressed.

To uncompress it use the following commands

% unzip [GovindarajanFinalProjectCSCI5742]

or unzip within downloads directory

Now you should see a directory named project with the files:

main.py

Readme.md

requirements.txt

Using a python compiler, you can use any run call to run the program


If there are problems with the import libraries, type the command below in your command prompt
with the path being your own, to enable installation of the import libraries:

pip install -r /pathto/GovindarajanFinalProjectCSCI5742/requirements.txt