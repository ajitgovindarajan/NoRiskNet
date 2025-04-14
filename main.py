#####################################
# CSCI 5742 CyberSecurity Programming and Analysis
# Final Project: Network Risk Assessment forum
# Ajit Govindarajan
# The purpose of this file is to denote the main file for the final project.
# The final project will be a Network risk analysis tool that will mimic scanning technology that we have used
# previously and incorporate the use of the CVE database and CVSS scoring to create the final vulnerability report on
# the IP address that are scanned and within the IP address, all the ports will be scanned to assess the
# relative security of the system.
# The classification will occur through the CVSS scoring and all of that will occur through the repository

import ipaddress
import json
# The summary will then include the final comprehensive the summary of how the security is relative to the allotted the
# budget and will give the best classification of the security
# Then the summary will include the recommendations as to how the security can be improved
######################################
# The socket library is used to scan the perspective socket ports through the iterations in the
# sockets
# The socket library allows for low-level interfaces between certain networks
import socket
import subprocess
import requests
# import nvdlib
# from nvdlib import Vulnerability
# from nvdlib.utils import get_cpe_uri_from_vendor_product_version


# Set IP range = [range of IP addresses to scan]
# The IP address scan will include all the machines that need to be scanned for
# vulnerabilities
# Set the list of IPs but maybe easier to set in CIDR notation
def IP():
    # this will start with program asking if there is a specif range of IPs that should be scanned
    print("How would you like the classify your network:")
    print("1) your IP address in CIDR notation? ")
    print("2) The default will be set from 192.168.0.0 to 192.168.0.255")
    print("3) A range of IP addresses with a starting and an ending address")
    choice = input(" will it be choice 1, choice 2, or choice 3")
    if choice == '1':
        ip_range = input("What is the range of IP addresses to scan (in CIDR notation)? ")
        # to create the full network, we can use the .hosts() command in the ipaddress library to create the network
        ip_network = ipaddress.ip_network(ip_range)
        return [str(ip) for ip in ip_network.hosts()]
    elif choice == '2':
        # IPlist = []
        start_of_IP = '192.168.0.0'
        end_of_IP = '192.168.0.255'
        IPlist = ranger(start_of_IP, end_of_IP)
        return IPlist
    elif choice == '3':
        # IPlist = []
        start_of_IP = input('What is the starting IP address? ')
        end_of_IP = input('What is the ending IP address? ')
        IPlist = ranger(start_of_IP, end_of_IP)
        return IPlist
    else:
        print("Invalid choice")


# this function below will create a range of IP addresses that will take the starting and the ending IP addresses
# and fill in an array of all the addresses in between with which that will be used for scanning
# code for this function was outlined by the source below
# https://stackoverflow.com/questions/20621485/how-can-i-seperate-ips-when-written-to-a-file
# and was altered for the purpose of this project
# https://datascience.stackexchange.com/questions/52626/complete-ipv4-address-list
def ranger(first_ip: str, last_ip: str) -> list[str]:
    # map out the listing of the starting with the periods as the split criteria
    begin = list(map(int, first_ip.split(".")))
    end = list(map(int, last_ip.split(".")))
    # initialize the empty list
    range_of_IPs = []

    # run through each possible address
    while begin <= end:
        # append to the list
        range_of_IPs.append(".".join(map(str, begin)))
        begin[3] += 1
        for i in range(3, 0, -1):
            if begin[i] == 256:
                begin[i] = 0
                begin[i-1] += 1

    # return the final range list
    return range_of_IPs


# 3. Set port scanner
# The port scanner will then scan all the ports within the IP address in the range
# will likely use Nmap due to increased familiarity with the nmap scans
# there will be a choice for the user or the cybersecurity professional on which
# ports are requested to be scanned
# parts of the port scanner was provided by the professor Dr.Haadi Jafarian in the lab 2
def Scan_port(ip, port_start, max_port):
    # set empty arrays to arrange the place where the ports will be placed
    open_TCP = []
    open_UDP = []
    open_ICMP = []
    # loop through all possible ports
    for i in range(port_start, max_port):
        # if the port is open in the TCP, add it to the list
        if scan_UDP(ip, i):
            # add the port to the list of open ports
            open_UDP.append(i)
        elif TCP(ip, i):
            # add the port to the lost of open ports
            open_TCP.append(i)
        elif icmp_scan(ip, i):
            open_ICMP.append(i)
        else:
            print("Port not available")
    return open_TCP, open_UDP, open_ICMP


# the UDP port scanner
# The UDP scanner was provided by the professor Dr.Haadi Jafarian in the lab 2
def scan_UDP(targetIP, portNumber):
    try:
        # in a port scanner we have to create a socket object
        scanned = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # the time inbetween the scanning ports to get packet through
        scanned.settimeout(1.0)
        # send the packet
        scanned.sendto(bytes("UDPPACKET", "utf-8"), (targetIP, portNumber))
        # return the data and the address
        response_data, response_address = scanned.recvfrom(65535)
        if response_data != None:
            return True
        else:
            return False
    except:
        print("Error has occurred Port", portNumber, " not reachable")


# parts of the TCP scanner was provided by the professor Dr.Haadi Jafarian in the lab 2
# this function will scan the TCP ports packets and output if they are sending a message
def TCP(targetIP, portNumber):
    try:
        # initialize the socket object to scan the TCP ports
        scanner_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # run the connection to the socket scanner
        scanner_socket.connect((targetIP, portNumber))
        # close the connection
        scanner_socket.close()
        return True
    except:
        print("Exception found Port", portNumber, " not reachable")
        return False


# The function below will scan the ICMP packets, similar to the TCP and UDP packet scanners above, this will highlight
# the ICMP response and find if packets are being sent through
def icmp_scan(ip, port):
    # Send a single ICMP echo request packet with a timeout of 1 second
    # the subprocess line has been derived from the link below
    # https://stackoverflow.com/questions/35750041/check-if-ping-was-successful-using-subprocess-in-python
    result = subprocess.run(['ping', '-c', '1', '-W', '1', str(ip)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # Check if the return code of the ping command is 0, indicating that the host is up
    if result.returncode == 0:
        print(f'{ip} is up')
        # Send an ICMP echo request packet to the specified port on the target IP address
        # A return code of 0 indicates that the port is open, while 1 indicates that it is closed
        # https://devconnected.com/how-to-ping-specific-port-number/
        cmd = f'ping -c 1 -p {port} -W 1 {ip} &> /dev/null'
        # https://www.programcreek.com/python/example/69299/subprocess.getstatusoutput
        status, result = subprocess.getstatusoutput(cmd)
        if status == 0:
            print(f'ICMP port {port} is open on {ip}')
        else:
            print(f'ICMP port {port} is closed on {ip}')
    else:
        print(f'{ip} is down,Port {port} not reachable')


# 4. Set CVE database = [online repository to fetch vulnerability data]
# Hit the online repository that contains the information about the vulnerabilities that are known
# The program  will use the repository database to get the data about the identified vulnerabilities on each
# of the machines
# This function will set the CVE ID and will generate the table of vulnerabilities that will help in the calculation
# of the cvss score for the vulnerability report
def vulner_metric(cve_id):
    global data
    """
    Fetches vulnerability data for a given CVE ID from the NVD API.
    """
    # set the database url
    # major problem based on how the url is taken
    base_url = "https://services.nvd.nist.gov/rest/json/cve/1.1/"
    """

    https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?name=CVE-2016-0051
    
    https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?name=
    """
    # set the URL for them to send the request
    url = f"{base_url}{cve_id}"
    # get the response from the request
    request = requests.get(url)
    # if the status code is 200, then there is a connection according to the source below
    # https: // developer.mozilla.org / en - US / docs / Web / HTTP / Status  # successful_responses
    if request.status_code == 200:
        # hit the data variable to store
        data = json.loads(request.text)

    else:
        print(f"No data found for {cve_id}.")
        return None

    # Alternate method using the nvdlib method in python
    # https://pypi.org/project/nvdlib/
    # cve_id = 'CVE-XXXX-XXXX'  # Replace with the CVE ID you want to extract metrics for
    # vulnerability = Vulnerability(cve_id)
    # if the data is present print out the data
    if data:
        # this will extract all the possible data from the CVE online repository
        # with the help of the json response library
        data2 = data['impact']['baseMetricV3']['cvssV3']
        metrics = {
            'impact': data2['impactScore'],
            'exploitability': data2['exploitabilityScore'],
            'scope': data2['scope'],
            'confidentiality': data2['confidentialityRequirement'],
            'integrity': data2['integrityRequirement'],
            'availability': data2['availabilityRequirement'],
            'attackVector': data2['attackVector'],
            'exploitCodeMaturity': data2['exploitCodeMaturity'],
            'remediationLevel': data2['remediationLevel'],
            'reportConfidence': data2['cvssV3MetaData']['exploitCodeMaturity']
        }
        return metrics


# https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?name=CVE-2016-0051
# This function will tke the metrics from the cve data and will send it through to calculate the cvss
# scores and provide another metric to the security score
# https://tsapps.nist.gov/publication/get_pdf.cfm?pub_id=50899
# Mell, P. , Kent, K. and Romanosky, S. (2006), Common Vulnerability Scoring System, IEEE Security & Privacy,
# [online], https://tsapps.nist.gov/publication/get_pdf.cfm?pub_id=50899 (Accessed May 1, 2023)
# The source above is where the true math model was extracted
def calculate_cvss_score(metrics):
    # Base Score and adjusted base score declaration
    global base_score, adjusted_base_score
    # based on the metrics, how will the equation be impacted
    impact = 1 - (1 - float(metrics['impact'])) * (1 - float(metrics['exploitability'])) * (1 - float(metrics['scope']))
    # based on the confidentiality metric, we can either factor in the confidentiality or not based on C,I, or A
    if metrics['confidentiality'] == 'C':
        impact *= 0.56
    elif metrics['confidentiality'] == 'I':
        impact *= 0.22
    elif metrics['confidentiality'] == 'A':
        impact *= 0

# the exploitability calculation will express the potential vulnerability that the machine might have
    exploitability = 20 * float(metrics['exploitability']) * float(metrics['remediationLevel']) * float(
        metrics['reportConfidence'])

    # looking at the attack vector we can take parts of the vector and extrapolate based on the math model to add to the
    # score
    if metrics['attackVector'] == 'N':
        base_score = impact * 0.85
    elif metrics['attackVector'] == 'A':
        base_score = impact * 0.62
    elif metrics['attackVector'] == 'L':
        base_score = impact * 0.55

    # Temporal Score calculation from the source above the
    temporal_score = base_score * float(metrics['exploitCodeMaturity']) * float(metrics['remediationLevel']) * float(
        metrics['reportConfidence'])

    # Environmental Score
    adjusted_impact = min(10.0, 10.41 * (1 - (1 - float(metrics['impact'])) * (1 - float(metrics['exploitability'])) * (
            1 - float(metrics['scope']))))
    # to classify the
    if metrics['confidentiality'] == 'C':
        adjusted_impact *= 1.5
    elif metrics['confidentiality'] == 'I':
        adjusted_impact *= 1.0
    elif metrics['confidentiality'] == 'A':
        adjusted_impact *= 0.5

    if metrics['attackVector'] == 'N':
        adjusted_base_score = adjusted_impact * 0.85
    elif metrics['attackVector'] == 'A':
        adjusted_base_score = adjusted_impact * 0.62
    elif metrics['attackVector'] == 'L':
        adjusted_base_score = adjusted_impact * 0.55
# the calculation of the environmental scores
    environmental_score = ((adjusted_base_score + (10 - adjusted_base_score) * float(
        metrics['confidentialityReq']) * float(metrics['integrityReq']) * float(metrics['availabilityReq'])) * float(
        metrics['exploitCodeMaturity']) * float(metrics['remediationLevel']) * float(metrics['reportConfidence']))
# return the main metrics from the scoring
    return {
        'base_score': round(base_score, 1),
        'temporal_score': round(temporal_score, 1),
        'environmental_score': round(environmental_score, 1)
    }


# This information will be used to fetch vulnerability data from the CVE database.
# b. Fetch vulnerability data for each service from CVE database
# The tool will use the CVE database to fetch data about the vulnerabilities associated with each service running on
# the machine. The data will include information about the CVSS base score for each vulnerability.
# c. Calculate CVSS base score for each vulnerability
# The tool will calculate the CVSS base score for each vulnerability identified on the machine.
# d. Aggregate CVSS base scores using vulnerability scoring model to get machine score
# The tool will use the selected vulnerability scoring model to aggregate the CVSS base scores and come up with a single
# score for the machine.
# e. Add machine score to machine scores dictionary with IP as key
# The machine score will be added to the machine scores dictionary with the IP address as the key.
def main():
    global machine_metric, cvss_score
    # 1. Set budget = [limited budget]
    # The budget will be a fixed amount that will likely represent the
    # budget to the IT budget accounted for
    # this will determine the extent to which the tool can perform its tasks
    budget = float(input("What is the allotted budget you have for your cyber defense? $"))

    TCP_ports = []
    UDP = []
    ICMP = []
    starter = 0
    end = 0

    # 7. For each IP in IP range:
    # Run port scanner on the IP to identify running services
    # The port scanner will be used to scan all the open ports on the machine and identify the services that are running
    print("Scanning for open ports")
    IPs = IP()

    # start of the menu to allow the network professional to choose if there are specif ports that need to be look
    # through and check to see if they are open
    print("Please select an option:")
    print("1. input an specific range of ports you want scanned")
    print("2. Choose a highest port number that will start from port 1 till that port(max is port 65536)")
    print("3. The default range will be from port 1 to port 1024")
    # what will the user choose
    porter = input("Choose between choice 1-3 ")
    # choice one will set the starting port to a user input
    # same for the maximum port
    if porter == "1":
        # ask for the input from the user about which ports they want scanned
        starter = int(input("What is the beginning of the port range you want scanned "))
        end = int(input("What is the last port you want scanned "))+1
    elif porter == "2":
        # Set the start at port 1
        starter = 1
        # input for the final port that will be scanned
        end = int(input("What is the last port you want scanned "))+1
        # need input validation to make sure the professional that is using the tool doesn't put an outside port range
        if end > 65536:
            print("The highest port is 65536, there are no ports outside of 65536, the default will be set at 1024")
            # set the default port at port 1024
            end = 1025
    # set the final option which is the standard scan from 1 to 1024
    elif porter == "3":
        starter = 1
        end = 1025

    # Now we will print the ports that have been found within the IP addresses
    for ip in IPs:
        TCP_ports, UDP, ICMP = Scan_port(ip, starter, end)
        print(f'Open TCP ports for {ip}: {TCP_ports}')
        print(f'Open UDP ports for {ip}: {UDP}')
        print(f'Open ICMP ports for {ip}: {ICMP}')
    # Collect CVE information for each open port found in the previous step
    # The CVE database will be queried for information about the vulnerabilities associated with each open port
    # then within the
    # loop through all open ports found in the previous step
    # The vulnerability scoring model is a mathematical model that will be used to aggregate the CVSS base scores.
    # 6. Set machine scores- an empty dictionary to store machine scores
    # This empty dictionary will be used to store the machine scores as they are calculated.
    # The scores will be added to the dictionary with the IP address as the key.
    print('Collecting CVE information...')
    print(" Is there a specified CVE-ID you want to use? ")
    print("1) Yes")
    print("2) No default will be CVE-2021-1001")
    us = input("Chose 1 or 2 ")
    if us == '1':
        # need to set CVE ID
        CVE = input("What is the preferred CVE ID that you want to scan the network through")
        machine_metric = {}
        for ip in IPs:
            for port in TCP_ports + UDP + ICMP:
                rep = vulner_metric(CVE)
                machine_metric[ip] = rep
                print(f'CVE information for port {port} on {ip}: {rep}')
    elif us == '2':
        machine_metric = {}
        cve_id = "CVE-2021-1001"
        for ip in IPs:
            for port in TCP_ports + UDP + ICMP:
                rep = vulner_metric(cve_id)
                machine_metric[ip] = rep
                print(f'CVE information for port {port} on {ip}: {rep}')
    else:
        print("Not a valid CVE ID")

    # Calculate the CVSSscore
    # for each vulnerability found in the previous step
    # The CVSS score will be calculated based on the CVE information collected in the previous step
    # The result of this calculation will be saved as an output file
    print('Calculating CVSS scores...')
    machine_scores = {}
    # loop through all open ports found in the previous step
    for ip in IPs:
        for port in TCP_ports + UDP + ICMP:
            for ip, metric in machine_metric.items():
                cvss_score = calculate_cvss_score(metric)
                machine_scores[ip] = cvss_score
            print(f'CVSS score for port {port} on {ip}: {cvss_score}')
    # print statement for the final scores that were found
    for ip, score in machine_scores.items():
        print(f"Machine {ip} has a vulnerability score of {score}")
        machine_scores[ip] = score
    # 8. Sort machines by score in descending order
    # The machine score will have to be sorted in descending order to then create a summary of machine security score
    # rankings
    for ip_address in machine_scores:
        machine_score = machine_scores[ip_address]
        overall_score = 0
        # now we need to accumulate a total score
        for cvss_score in machine_score:
            overall_score += cvss_score
            # get an overall score for the network
        machine_scores[ip_address] = overall_score

    # 12. Sort the machines based on their vulnerability score
    # https://www.w3schools.com/python/python_lambda.asp
    # https://www.geeksforgeeks.org/python-sorted-function/#
    # The lambda function is uses to sort through the score and dictate which is the best cvss score
    # the sorted function that is built in to python that allows for easy sorting using the lambda algorithm
    sorted_machines = sorted(machine_scores.items(), key=lambda x: x[1], reverse=True)
    print(sorted_machines)
    # 9. Print machine scores in the following format:
    # Summary of machine security score rankings based on aggregated risk scores
    # The summary will include a list of the machines in order of their security score, along with the score itself.
    # b. Detailed report on services/vulnerabilities discovered on each machine
    # The detailed report will include information about the services and vulnerabilities discovered on each machine,
    # along with their CVSS base scores.
    # The report could also include recommendations for addressing the vulnerabilities.
    # then send to the generate report function to output the final report
    final_report = " "
    for ip in IPs:
        for score in sorted_machines:
            final_report = generate_report(ip, machine_metric, score)

        print(final_report)
    # along with the reports for each IP, the budget that is being spent will be outlined for a complete summary
    print("With a budget of $", budget, " The report states your relative security")


# this function below will generate the report of the final vulnerabilities and then output the
# final verdicts on what is happening with in the network
# this report will highlight the finding of the CVE database and also
# print out the comprehensive
def generate_report(ip, vulnerabilities, cvssScore):
    # title header of the report
    report = "Vulnerability Report: for ip :\n\n", ip
    # cycle through the data to print it out
    for vulnerability in vulnerabilities:
        # add to the report each of the main metrics
        # the id
        report += f"ID: {vulnerability['id']}\n"
        # how severe the vulnerability is
        report += f"Severity: {vulnerability['severity']}\n"
        # short description connected to the vulnerability
        report += f"Description: {vulnerability['description']}\n"
        # print out the cvss score
        report += f"CVSS Score: {cvssScore}\n"
        # then shows the affected systems
        report += f"Affected Systems: {vulnerability['affected_systems']}\n"
    return report


if __name__ == '__main__':
    main()
