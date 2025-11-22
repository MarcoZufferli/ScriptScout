import argparse
import os
import sys
import shlex
from termcolor import colored
import re
import subprocess
import dns.resolver
import time
from random import SystemRandom
import ntpath
import random
from impacket.smbconnection import SMBConnection, SessionError
from impacket import nt_errors

# Main
def main():

	#banner
	banner()

	# Creation of the "--help" menu & arguments
	parser = argparse.ArgumentParser()
	parser.add_argument('-u', '--username', help="Insert the username", required=True)
	parser.add_argument('-p', '--password', help="Insert the password of the username", required=True)
	parser.add_argument('-d', '--domain', help="Insert the FULL domain of the username (e.g. WORLD.local is valid, WORLD is NOT valid)", required=True)
	parser.add_argument('-ip-dc', '--ip_address_domain_controller', help="Insert the IP Address of the Domain Controller target", required=True)
	parser.add_argument('-t', '--technique', help="Select the techinique to test (ALL | SMISC1 | SMISC2_and_SMISC3 | SMISC4 | SMISC5), by default it's ALL", default = "ALL")
	parser.add_argument('-opsec', '--opsec', help="Select the desired OPSEC level (ZERO | MEDIUM | HIGH), higher means longer sleep; by default it's MEDIUM", default ="MEDIUM")
	parser.add_argument('-la', '--legal_authorization_check', help="Confirm you have prior explicit written authorization from the infrastructure owner to run this tool; unauthorized or improper use is illegal and entirely the user's responsibility; the author disclaims all warranties and any liability for misuse or damages. ( Y | N ) (by default it's N)", default ="N", required=True)

	argsparsed = parser.parse_args()

	if ("MEDIUM" in argsparsed.opsec):
		starting_time = 1.5
		final_time = 2.5
	elif ("HIGH" in argsparsed.opsec):
		starting_time = 3
		final_time = 5
	elif ("ZERO" in argsparsed.opsec):
		starting_time = 0
		final_time = 0.01
	else:
		print("You have selected an invalid OPSEC level, please try again")
		exit()

	if ("." not in argsparsed.domain): ## For how does it works some check we need to use the FQDN of the domain.

		print("\"" + argsparsed.domain + "\" is not valid; you must insert the FQDN of the domain (e.g. WORLD.local is valid, WORLD is NOT valid)")
		exit()

	if (argsparsed.legal_authorization_check.strip().upper() != "Y"):

		print("The \"-la\" / \"--legal-authorization\" parameter is mandatory.\n")
		print("Legal authorization check failed: you must confirm you have explicit written consent to use this tool.")
		exit()

	if ("ALL" in argsparsed.technique):

		collect_scripts(argsparsed.username,argsparsed.password,argsparsed.domain,argsparsed.ip_address_domain_controller,starting_time,final_time)
		SMISC_1()
		SMISC_2_and_3(argsparsed.username,argsparsed.password,argsparsed.domain,argsparsed.ip_address_domain_controller,starting_time,final_time)
		SMISC_4(argsparsed.username,argsparsed.password,argsparsed.domain,argsparsed.ip_address_domain_controller,starting_time,final_time)
		SMISC_5(argsparsed.domain,argsparsed.ip_address_domain_controller,starting_time,final_time)

	if ("SMISC1" in argsparsed.technique):

		collect_scripts(argsparsed.username,argsparsed.password,argsparsed.domain,argsparsed.ip_address_domain_controller,starting_time,final_time)
		SMISC_1()

	if ("SMISC2_and_SMISC3" in argsparsed.technique):

		collect_scripts(argsparsed.username,argsparsed.password,argsparsed.domain,argsparsed.ip_address_domain_controller,starting_time,final_time)
		SMISC_2_and_3(argsparsed.username,argsparsed.password,argsparsed.domain,argsparsed.ip_address_domain_controller,starting_time,final_time)

	if ("SMISC4" in argsparsed.technique):

		collect_scripts(argsparsed.username,argsparsed.password,argsparsed.domain,argsparsed.ip_address_domain_controller,starting_time,final_time)
		SMISC_4(argsparsed.username,argsparsed.password,argsparsed.domain,argsparsed.ip_address_domain_controller,starting_time,final_time)

	if ("SMISC5" in argsparsed.technique):

		collect_scripts(argsparsed.username,argsparsed.password,argsparsed.domain,argsparsed.ip_address_domain_controller)
		SMISC_5(argsparsed.domain,argsparsed.ip_address_domain_controller,starting_time,final_time)

def banner():
	print("""
 _______  _______  ______    ___   _______  _______  _______  _______  _______  __   __  _______
|       ||       ||    _ |  |   | |       ||       ||       ||       ||       ||  | |  ||       |
|  _____||       ||   | ||  |   | |    _  ||_     _||  _____||       ||   _   ||  | |  ||_     _|
| |_____ |       ||   |_||_ |   | |   |_| |  |   |  | |_____ |       ||  | |  ||  |_|  |  |   |  
|_____  ||      _||    __  ||   | |    ___|  |   |  |_____  ||      _||  |_|  ||       |  |   |  
 _____| ||     |_ |   |  | ||   | |   |      |   |   _____| ||     |_ |       ||       |  |   |  
|_______||_______||___|  |_||___| |___|      |___|  |_______||_______||_______||_______|  |___|

""")

def collect_scripts(username, password, domain, ip_address_domain_controller, starting_time, final_time):

	# Folder creation 
	current_path = os.getcwd()
	destination_path = current_path + "/scripts_collected/"
	destination_path_scheduledtask_conf = current_path + "/ScheduledTaskConf_collected/"

	try:
		os.mkdir(destination_path)
	except:
		print("The \"./scripts_collected\" folder has been already created, delete it before to run it again")
		exit()

	try:
		os.mkdir(destination_path_scheduledtask_conf)
	except:
		print("The \"./ScheduledTaskConf_collected\" folder has been already created, delete it before to run it again")
		exit()

	DC_IP = ip_address_domain_controller
	DOMAIN = domain
	USERNAME = username
	PASSWORD = password
	SHARE = "SYSVOL"

	# NTLM login to the DC
	conn = SMBConnection(remoteName=DC_IP, remoteHost=DC_IP, sess_port=445)
	try:
		conn.login(USERNAME, PASSWORD, DOMAIN)
	except SessionError as e:
		if e.getErrorCode() in (nt_errors.STATUS_LOGON_FAILURE, nt_errors.STATUS_ACCESS_DENIED):
			print("The domain controller rejected your credentials (Logon Failure / Access Denied), please verify your domain username and password and try again.")
			exit()

	print("Downloading AD Automation Script (from: \"/SYSVOL/<domain>/scripts/* & \"/SYSVOL/<domain>/Policies/<GPO_GUID>/<User OR Machine>/scripts/<Logon OR Logoff OR StartUp Or Shutdown/*\") and Scheduled Task Configuration (\"/SYSVOL/<domain>/Policies/<GPO_GUID>/<User OR Machine>/Preferences/ScheduledTasks/*\") is in progress...")

	# 1) Download every file (only script should be there) in "\SYSVOL\<domain>\scripts"

	scripts_dir = ntpath.join("\\", DOMAIN, "scripts")  # Uses ntpath to safely build the Windows path; here it creates "\MARVEL.local\scripts"
	for entry in conn.listPath(SHARE, ntpath.join(scripts_dir, "*")): # It list every file inside "\MARVEL.local\scripts" and for each of them (using the for iteration) we perform some activites
	    name = entry.get_longname() # Retrieve the name of the file
	    if name in (".", "..") or entry.is_directory(): # We skip the "fake entries" that point to the current and parent folder that we have using this function, so we analyze only the real filename
	        continue
	    remote_path = ntpath.join(scripts_dir, name) # Combine script dir (e.g., \MARVEL.local\scripts) with the remote filename (e.g \logonscript.ps), so obtaing for example \MARVEL.local\script\logonscript.ps1
	    local_name = f"{DC_IP}-SYSVOL_{DOMAIN}_Scripts_{name}" # Build the local filename (e.g., "192.168.52.130-SYSVOL_MARVEL.local_scripts_Deploy.ps1")
	    with open(local_name, "wb") as fh: # Create the local file using the syntax indicated above, then read the remote file (e.g. "logonscript.ps1") and save the output on the local file
	        conn.getFile(SHARE, remote_path, fh.write)
	    jitter(starting_time,final_time)

	# 2) Download every file (only script should be there) in "/SYSVOL/<domain>/Policies/<GPO_GUID>/<User OR Machine>/scripts/<Logon OR Logoff OR StartUp Or Shutdown/*"", so every GPO Script.

	pol_root = ntpath.join("\\", DOMAIN, "Policies") # Uses ntpath to safely build the Windows path; it in this case it creates "\<domain>\Policies".
	guid_re = re.compile(r"^\{[0-9A-Fa-f\-]{36}\}$") # Create a regex that match only the GPO GUID directory names (it's not so usefull since the folder "\Policies" has only GUID but that's a nice to have)

	# Subpath needed (User and Machine)
	subpaths = [
	    ("User", "Scripts", "Logon"), # GPO Logon Script (Users)
	    ("User", "Scripts", "Logoff"), # GPO Logoff Script (Users)
	    ("Machine", "Scripts", "Startup"), # GPO StartUp Script (Computer)
	    ("Machine", "Scripts", "Shutdown"), # GPO Shutdown Script (Computer)
	    ("User", "Preferences", "ScheduledTasks"), # GPO Scheduled Task (User)
	    ("Machine", "Preferences", "ScheduledTasks"), # GPO Scheduled Task (Computer)
	]

	# Enumerate all existing GPO GUIDs
	guids = [] # Initialize the list that will hold all GPO GUIDs found
	for e in conn.listPath(SHARE, ntpath.join(pol_root, "*")): # List entries under "\SYSVOL\<domain>\Policies" and iterate over them
	    if e.is_directory() and guid_re.match(e.get_longname()): # Retrive the first entry, then check if it’s a directory &  matches the GPO GUID pattern
	        guids.append(e.get_longname()) # If yes, add it to the GUID list called "guids".

	# Download all GPO-related Automation Scripts
	for guid in guids: # Iterate each GPO folder (e.g., \SYSVOL\<domain>\Policies\<GUID>)
	    for parts in subpaths: # For each predefined subpath (e.g Users\Scripts\Logon)
	        base_dir = ntpath.join(pol_root, guid, *parts) # Build the "pol_root" string ("\SYSVOL\<domain>\Policies") with the "guid" string (\<GUID>\) and with the first (since it's the first iteration) entry of the "subpath" value, so the "part" string ("\Users\Scripts\Logon"), so we can say that "base_dir" is for example in the first iteration this following value: "\MARVEL.local\Policies\{GUID}\User\Scripts\Logon"
	        try:
	            for e in conn.listPath(SHARE, ntpath.join(base_dir, "*")): # # List entries in the target subfolder (e.g. "\MARVEL.local\Policies\{GUID}\User\Scripts\Logon\") and iterate over them.
	                name = e.get_longname() # Retrieve the name of the file
	                if name in (".", "..") or e.is_directory(): # We skip the "fake entries" that point to the current and parent folder that we have using this function, so we analyze only the real filename
	                    continue
	                remote_path = ntpath.join(base_dir, name) # Build the full path of the remote file (e.g. "\MARVEL.local\Policies\{GUID}\User\Scripts\Logon\script.ps1")
	                tag = "_".join(p for p in parts)
	                local_name = f"{DC_IP}-SYSVOL_{DOMAIN}_policies_{guid}_{tag}_{name}" # Build the local filename for the downloaded script
	                with open(local_name, "wb") as fh: # Finaly create the local file
	                    conn.getFile(SHARE, remote_path, fh.write)  # Download the remote file
	                jitter(starting_time,final_time)
	                # After sleeping, proceed with the other subpaths (e.g. "\MARVEL.local\Policies\{GUID}\User\Scripts\Logoff") and so on until finishing the "subpaths" & "guids" lists
	        except Exception:
	            pass

	# Close the SMB Connection
	conn.logoff()

	# Move the ScheduledTask configuration file into a new folder called "ScheduledTaskConf_collected"
	cmd = ("find . -maxdepth 1 -type f -name \"*Preferences*\" -exec mv {} " + destination_path_scheduledtask_conf + " " + "\\;")
	#print(cmd)
	os.system(cmd)

	# Move the scripted collected into a new folder called "scripts_collected"
	cmd = ("mv " + ip_address_domain_controller + "-SYSVOL*" + " " + destination_path)
	#print(cmd)
	os.system(cmd)

def SMISC_1():

	print(colored('\nSMISC1: Plaintext Credential Stored inside Scripts:\n', 'yellow', attrs=['bold', 'underline']))

	current_path = os.getcwd()
	destination_path = current_path + "/scripts_collected/"

	# RegExp that find harcoded credential durint the mapping of a File Share SMB - ChatGPT
	regexp = r'''(?:(?:net\s+use|New-PSDrive|MapNetworkDrive).*(?:\/user:|[\s\/]-credential|[\s,]\s*"?[^"]*\\[^"]*"?\s*[,\s]).*(?:\/|\s|[,"])[^\/\s]*(?:\$|[a-zA-Z0-9!@#$%^&*()_+={}[\]:;"<>,.?/~`-]+))|(?:\\\\[a-zA-Z0-9.-]+\\[a-zA-Z0-9$._-]+.*(?:password|pwd|pass|user|username|credential)[^a-zA-Z0-9]*[a-zA-Z0-9!@#$%^&*()_+={}[\]:;"<>,.?/~`-]+)'''

	cmd = "grep --color=always -P -i -r -H " + shlex.quote(regexp) + " " + shlex.quote(destination_path)
	#print(cmd)
	os.system(cmd)
	print("\r")

def SMISC_2_and_3(username, password, domain, ip_address_domain_controller, starting_time, final_time):

	print(colored('\nSMISC2 & SMISC3: Find a Script that interacts with data having excessive permissions:\n', 'yellow', attrs=['bold', 'underline']))
	print(colored(' -- SMISC2: Find a Script that execute a remote file hosted on a SMB Share, where the file itself or its parent folder / SMB share has excessive permissions (so the file inherits those permissions).', 'yellow', attrs=['bold']))
	print(colored(' -- SMISC3: Find a Script that executes a non-existent remote file hosted on an SMB share, where its parent folder / SMB share has excessive permissions.\n', 'yellow', attrs=['bold']))
	
	print("Note 1: Since modifying a file (SMISC2) or creating a new file (SMISC3) requires both NTFS & SMB share permissions and ScriptScout can only identify the first, the simplest way to verify the SMB share permissions is by attempting an attack, if the attack succeeds, it confirms that both permission layers are properly configured.")
	print("\r")
	print("Note 2: This check involves a direct connection to the remote SMB share, so, if the machine from which you run this script does not have proper connectivity to the targets, the coverage of the script will be incomplete.")
	print("\r")
	print("Note 3: If misconfiguration (SMISC2 and / or SMISC3) are detected, you can identify which script contains the misconfiguration by reviewing the \"SMISC2_unc_path_extracted_with_hostname_and_ip.txt\" file; furthermore, if the related script is executed through a Scheduled Task or not, you can manually verify this by checking whether the script is referenced in a \"Scheduled Task.xml\" file within the ./ScheduledTaskConf_collected/ folder (you can use the \"grep\" utility).")

	print("\r")

	current_path = os.getcwd()
	destination_path = current_path + "/scripts_collected/"

	## Creating several file as prerequisite ---

	# RegExp that find UNC Path that point to a file
	unc_regexp = r'(?i)\\\\(?:[A-Za-z0-9._-]+|\\[[A-Fa-f0-9:]+\\])\\(?:[^\\\r\n"]+\\)*[^\\\r\n"]+\.(?:exe|bat|cmd|ps1|vbs|js|jse|wsf|hta|msi|msu|dll|sct)\b'
	
	# Create a temp file 1 called "/script_collected/SMISC2_unc_path_extracted.txt"
	cmd = "grep -P -i -r -H " + shlex.quote(unc_regexp) + " " + shlex.quote(destination_path) + " | sort -n | uniq > " + "SMISC2_unc_path_extracted.txt 2>/dev/null"
	#print(cmd)
	os.system(cmd)

	# RegExp that extrapolate hostname from every UNC Path file that points to a file
	hostname_from_unc_regexp = r'^\\\\\K[^\\]+'

	# Create a temp file 2 called "/SMISC2_list_hostname_indicated_inside_unc.txt"
	cmd = "cat SMISC2_unc_path_extracted.txt | cut -d ':' -f 2 | grep -oP " + shlex.quote(hostname_from_unc_regexp) + " > " + "SMISC2_unc_path_extracted_only_hostname.txt 2>/dev/null"
	#print(cmd)
	os.system(cmd)

	if (os.path.getsize("SMISC2_unc_path_extracted_only_hostname.txt")) & (os.path.getsize("SMISC2_unc_path_extracted_only_hostname.txt")) == 0: # if these file are empty, there are not Automation Script that execute remote file hosted on SMB Share, so no SMISC2 & SMISC3
		os.remove("SMISC2_unc_path_extracted.txt")
		os.remove("SMISC2_unc_path_extracted_only_hostname.txt")
		return; # Exit from the function SMISC2 & SMISC3, otherwise it will trigger an error further on

	## DNS Lookup in order to retrieve the Record A of each hostname inside the UNC Path in order to perform the next activities ---

	hostnames = open("SMISC2_unc_path_extracted_only_hostname.txt", "r")

	for hostname in hostnames:

		hostname = hostname.rstrip("\r\n") # Remove \r\n
		dnsquery = dns.resolver.Resolver(configure=False)
		dnsquery.nameservers = [ip_address_domain_controller]

		try:
		    results = dnsquery.resolve(hostname + "." + domain, 'A') # Execute DNS Query
		    jitter(starting_time,final_time) # Sleep
		    for ip in results:
		    	os.system("echo " + "'" + str(ip) + "'" + ">> SMISC2_unc_path_extracted_only_hostname-IP.txt") ## We create a new file and for each successfully record A retrived we put this data into that file

		except dns.resolver.NXDOMAIN:
		    os.system("echo 'N/A-NXDOMAIN' >> SMISC2_unc_path_extracted_only_hostname-IP.txt")  ## For each NOT successfully record A retrived we put this data into the file previusly created

	# Starting File (it will be modified)
	percorso_a = "SMISC2_unc_path_extracted.txt"
	# File with the entries that we want to append into the Starting File
	percorso_b = "SMISC2_unc_path_extracted_only_hostname-IP.txt"
	# Separator
	sep = ":"

	# We are appending the Record A retrieved inside the corrisponding "SMISC2_unc_path_extracted.txt"
	with open(percorso_a, "r", encoding="utf-8") as fa:
	    righe_a = fa.readlines()
	with open(percorso_b, "r", encoding="utf-8") as fb:
	    righe_b = fb.readlines()
	with open(percorso_a, "w", encoding="utf-8") as fa:
	    for a, b in zip(righe_a, righe_b):
	        fa.write(a.rstrip("\n") + sep + b.rstrip("\n") + "\n")

	# Now that the file "SMISC2_unc_path_extracted.txt" contains everything we can rename it
	os.system("mv SMISC2_unc_path_extracted.txt SMISC2_unc_path_extracted_with_hostname_and_ip.txt")

	## Preparation & launch smbcacls

	# RegExp that find UNC Path that point to a file
	unc_regexp2 = r'{gsub(/\\/, "/"); print gensub(/^\/\/([^\/]+)\/([^\/]+)(\/.*)$/, "//\\1/\\2 \\3", 1)}'

	# Create a temp file 3 called "/script_collected/SMISC2_unc_path_extracted_uniq_for_smbcacls.txt"
	cmd = "cat SMISC2_unc_path_extracted_with_hostname_and_ip.txt | cut -d \":\" -f 2 | awk " + "'" + unc_regexp2 + "'" + " > SMISC2_unc_path_extracted_for_smbcacls.txt"
	#print(cmd)
	os.system(cmd)

	# RegExp that use AWK to generate the final file to give to smbcacls
	regexp_awk = r'NR==FNR{ip[NR]=$0; next}{p=index($0,"/"); s=index(substr($0,p+2),"/")+p+1; resto=substr($0,s); print "//" ip[FNR] resto}'

	cmd = "awk " + shlex.quote(regexp_awk) + " SMISC2_unc_path_extracted_only_hostname-IP.txt SMISC2_unc_path_extracted_for_smbcacls.txt | grep -v 'NXDOMAIN' > SMISC2_for_smbcacls.txt"
	#print(cmd)
	os.system(cmd)

	# Do the smbcacls checks

	with open("SMISC2_for_smbcacls.txt", "r", encoding="utf-8") as file:

		for righe in file:

			full_username = domain + "\\\\" + username
			cmd = ("smbcacls " + str(righe).rstrip('\n') + " -U " + full_username + " --password " + password)
			#print(cmd)
			jitter(starting_time,final_time)

			result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

			## SMISC3 control
			if "NT_STATUS_OBJECT_NAME_NOT_FOUND" in result.stdout:

				path_line = str(righe).rstrip('\n') # e.g. from -> //192.168.1.1/business_folder /management_files/notexistfile.bat
				parent_path = path_line.rsplit('/', 1)[0] # e.g. to -> //192.168.1.1/business_folder /management_files/
				#print(parent_path)

				cmd_SMISC3 = ("smbcacls " + str(parent_path).rstrip('\n') + " -U " + full_username + " --password " + password)

				## SMISC3 control

				dom_splitted1 = domain.split('.')[0] ## It retrieve the "domain" input, like "MARVEL.local", "IT.MARVEL.local" or "SUB.IT.MARVEL.local" and extrapulate only the "current" domain, so: "MARVEL", "IT" or "SUB"; this is the syntax that wants SMBCacls in some entries (with this syntax the tool will works targetting also DC that host a Child Domain)

				# Everyone Group & Domain Users Group include ALL the Domain Users ("User" AD Object)
				# Having only "Write" permission could be in theory exploitable, however, without "the Read" permission the "smbcacls" tool will always return "Access Denied" making it impossible to enumerate this permission with the tool.

				string_excessive_permissions_parent_path1 = [
				r"ACL:Everyone:ALLOWED/OI|CI/FULL", # Everyone - FullControl
				r"ACL:Everyone:ALLOWED/OI|CI|I/FULL", # Everyone - Same as above but this permission is inherited (indicated by 'I') from the hierarchical structure of the containing folder
				r"ACL:Everyone:ALLOWED/OI|CI/RW", # Everyone - Read & Write (since the check is "contains" and not "exact match", this reg will match also for "RWXD" (Modify, Read & Execute, List folder contents, Read, Write) & "RWX" (Read & Execute, List folder contents, Read, Write)
				r"ACL:Everyone:ALLOWED/OI|CI|I/RW", # Everyone - Same as above but this permission is inherited (indicated by 'I') from the hierarchical structure of the containing folder
				rf"ACL:{dom_splitted1}\Domain Users:ALLOWED/OI|CI/FULL", # Domain Users - FullControl
				rf"ACL:{dom_splitted1}\Domain Users:ALLOWED/OI|CI|I/FULL", # Domain Users - Same as above but this permission is inherited (indicated by 'I') from the hierarchical structure of the containing folder
				rf"ACL:{dom_splitted1}\Domain Users:ALLOWED/OI|CI/RW", # Domain Users - Read & Write (since the check is "contains" and not "exact match", this reg will match also for "RWXD" (Modify, Read & Execute, List folder contents, Read, Write) & "RWX" (Read & Execute, List folder contents, Read, Write)
				rf"ACL:{dom_splitted1}\Domain Users:ALLOWED/OI|CI|I/RW", # - Same as above but this permission is inherited (indicated by 'I') from the hierarchical structure of the containing folder
				]

				# Authenticated Users Group include ALL Domain Users ("User" AD Object) & Computer Account ("Computer" AD Object)
				# Having only "Write" permission could be in theory exploitable, however, without "the Read" permission the "smbcacls" tool will always return "Access Denied" making it impossible to enumerate this permission with the tool.

				string_excessive_permissions_parent_path2 = [
				r"ACL:NT AUTHORITY\Authenticated Users:ALLOWED/OI|CI/FULL", # Authenticated Users - FullControl
				r"ACL:NT AUTHORITY\Authenticated Users:ALLOWED/OI|CI|I/FULL", # Authenticated Users - Same as above but this permission is inherited (indicated by 'I') from the hierarchical structure of the containing folder
				r"ACL:NT AUTHORITY\Authenticated Users:ALLOWED/OI|CI/RW", # Authenticated Users - Read & Write (since the check is "contains" and not "exact match", this reg will match also for "RWXD" (Modify, Read & Execute, List folder contents, Read, Write)) & "RWX" (Read & Execute, List folder contents, Read, Write)
				r"ACL:NT AUTHORITY\Authenticated Users:ALLOWED/OI|CI|I/RW" # Authenticated Users - Same as above but this permission is inherited (indicated by 'I') from the hierarchical structure of the containing folder
				]

				# Domain Computers Group include ALL Computer Account ("Computer" AD Object)
				# Having only "Write" permission could be in theory exploitable, however, without "the Read" permission the "smbcacls" tool will always return "Access Denied" making it impossible to enumerate this permission with the tool.

				string_excessive_permissions_parent_path3 = [
				rf"ACL:{dom_splitted1}\Domain Computers:ALLOWED/OI|CI/FULL", # Domain Computers - FullControl
				rf"ACL:{dom_splitted1}\Domain Computers:ALLOWED/OI|CI|I/FULL", # Domain Computers - Same as above but this permission is inherited (indicated by 'I') from the hierarchical structure of the containing folder
				rf"ACL:{dom_splitted1}\Domain Computers:ALLOWED/OI|CI/RW", # Read & Write (since the check is "contains" and not "exact match", this reg will match also for "RWXD" (Modify, Read & Execute, List folder contents, Read, Write)) & "RWX" (Read & Execute, List folder contents, Read, Write)
				rf"ACL:{dom_splitted1}\Domain Computers:ALLOWED/OI|CI|I/RW", # Domain Computers - Same as above but this permission is inherited (indicated by 'I') from the hierarchical structure of the containing folder
				]

				# Having only "Write" permission could be in theory exploitable, however, without "the Read" permission the "smbcacls" tool will always return "Access Denied" making it impossible to enumerate this permission with the tool.

				#print(cmd_SMISC3)

				
				result2 = subprocess.run(cmd_SMISC3, shell=True, capture_output=True, text=True)

				out2 = result2.stdout

				if any(s in str(out2) for s in string_excessive_permissions_parent_path1):
					print(colored("SMISC3: Although the file does not exist, since the corresponding parent folder has excessive permissions (at \"Everyone\" Group OR \"Domain Users\" Users Group), an attacker (impersonating a Domain User) could create an arbitrary file named exactly as the non-existent filename in order to hijack it: ",'red', attrs=['bold']),end="")
					print(colored(righe + "\n",'magenta',attrs=['bold']),end="")

				if any(s in str(out2) for s in string_excessive_permissions_parent_path2):
					print(colored("SMISC3: Although the file does not exist, since the corresponding parent folder has excessive permissions (at \"Authenticated Users\" Group), an attacker impersonating a Domain User OR a Computer Account (e.g. compromising a Computer or Creating a new Computer Account abusing the default \"MS-DS-Machine-Account-Quota\" value) could create an arbitrary file named exactly as the non-existent filename in order to hijack it: ",'red', attrs=['bold']),end="")
					print(colored(righe + "\n",'magenta',attrs=['bold']),end="")

				if any(s in str(out2) for s in string_excessive_permissions_parent_path3):
					print(colored("SMISC3: Although the file does not exist, since the corresponding parent folder has excessive permissions (at \"Computer Account\" Group) an attacker impersonating a Computer Account (e.g. compromising a Computer or Creating a new Computer Account abusing the default \"MS-DS-Machine-Account-Quota\" value) could create an arbitrary file named exactly as the non-existent filename in order to hijack it: ",'red', attrs=['bold']),end="")
					print(colored(righe + "\n",'magenta',attrs=['bold']),end="")

			## SMISC2 control

			dom_splitted2 = domain.split('.')[0] ## It retrieve the "domain" input, like "MARVEL.local", "IT.MARVEL.local" or "SUB.IT.MARVEL.local" and extrapulate only the "current" domain, so: "MARVEL", "IT" or "SUB"; this is the syntax that wants SMBCacls in some entries. (with this syntax it will works also targetting DC that host a Child Domain)

			# Everyone Group & Domain Users Group include ALL the Domain Users ("User" AD Object)
			# Having only "Write" permission could be in theory exploitable, however, without "the Read" permission the "smbcacls" tool will always return "Access Denied" making it impossible to enumerate this permission with the tool.

			string_excessive_permissions_file1 = [
			r"ACL:Everyone:ALLOWED/0x0/FULL", # Everyone - FullControl
			r"ACL:Everyone:ALLOWED/I/FULL", # Everyone - Same as above but this permission is inherited (indicated by 'I') from the hierarchical structure of the containing folder
			r"ACL:Everyone:ALLOWED/0x0/RW", # Everyone - Read & Write (since the check is "contains" and not "exact match", this reg will match also for "RWXD" (Modify, Read & Execute, Read, Write) & "RWX" (Read & Execute, Read, Write)
			r"ACL:Everyone:ALLOWED/I/RW", # Everyone - Same as above but this permission is inherited (indicated by 'I') from the hierarchical structure of the containing folder
			rf"ACL:{dom_splitted2}\Domain Users:ALLOWED/0x0/FULL", # Domain Users - FullControl
			rf"ACL:{dom_splitted2}\Domain Users:ALLOWED/I/FULL", # Domain Users - Same as above but this permission is inherited (indicated by 'I') from the hierarchical structure of the containing folder
			rf"ACL:{dom_splitted2}\Domain Users:ALLOWED/0x0/RW", # Domain Users - Read & Write (since the check is "contains" and not "exact match", this reg will match also for "RWXD" (Modify, Read & Execute, Read, Write) & "RWX" (Read & Execute, Read, Write)
			rf"ACL:{dom_splitted2}\Domain Users:ALLOWED/I/RW", # Domain Users - Same as above but this permission is inherited (indicated by 'I') from the hierarchical structure of the containing folder
			]

			# Authenticated Users Group include ALL Domain Users ("User" AD Object) & Computer Account ("Computer" AD Object)
			# Having only "Write" permission could be in theory exploitable, however, without "the Read" permission the "smbcacls" tool will always return "Access Denied" making it impossible to enumerate this permission with the tool.
			
			string_excessive_permissions_file2 = [
			r"ACL:NT AUTHORITY\Authenticated Users:ALLOWED/0x0/FULL", # Authenticated Users FullControl
			r"ACL:NT AUTHORITY\Authenticated Users:ALLOWED/I/FULL",  # Authenticated Users - Same as above but this permission is inherited (indicated by 'I') from the hierarchical structure of the containing folder
			r"ACL:NT AUTHORITY\Authenticated Users:ALLOWED/0x0/RW", # Authenticated Users - Read & Write (since the check is "contains" and not "exact match", this reg will match also for "RWXD" (Modify, Read & Execute, Read, Write) & "RWX" (Read & Execute, Read, Write)
			r"ACL:NT AUTHORITY\Authenticated Users:ALLOWED/I/RW" # Authenticated Users - Same as above but this permission is inherited (indicated by 'I') from the hierarchical structure of the containing folder
			]

			# Domain Computers Group include ALL Computer Account ("Computer" AD Object)
			# Having only "Write" permission could be in theory exploitable, however, without "the Read" permission the "smbcacls" tool will always return "Access Denied" making it impossible to enumerate this permission with the tool.

			string_excessive_permissions_file3 = [
			rf"ACL:{dom_splitted2}\Domain Computers:ALLOWED/0x0/FULL", # Domain Computer Users FullControl
			rf"ACL:{dom_splitted2}\Domain Computers:ALLOWED/I/FULL",  # Domain Computer - Same as above but this permission is inherited (indicated by 'I') from the hierarchical structure of the containing folder
			rf"ACL:{dom_splitted2}\Domain Computers:ALLOWED/0x0/RW", # Domain Computer - Read & Write (since the check is "contains" and not "exact match", this reg will match also for "RWXD" (Modify, Read & Execute, Read, Write) & "RWX" (Read & Execute, Read, Write)
			rf"ACL:{dom_splitted2}\Domain Computers:ALLOWED/I/RW" # Domain Computer - Same as above but this permission is inherited (indicated by 'I') from the hierarchical structure of the containing folder
			]
			
			# Having only "Write" permission could be in theory exploitable, however, without "the Read" permission the "smbcacls" tool will always return "Access Denied" making it impossible to enumerate this permission with the tool.
	
			out = result.stdout

			if any(s in str(out) for s in string_excessive_permissions_file1):

				print(colored("SMISC2: This remote file: ",'red', attrs=['bold']),end="")
				print(colored(righe.rstrip('\n'),'magenta',attrs=['bold']),end="")
				print(colored(" has excessive permission (at \"Everyone\" Group OR \"Domain Users\" Users Group) - it means an attacker impersonating a Domain User could modify the target file by inserting any malicious payload which would then be potentially executed by the victim." ,'red', attrs=['bold']))

				print("\r")

			if any(s in str(out) for s in string_excessive_permissions_file2):

				print(colored("SMISC2: This remote file: ",'red', attrs=['bold']),end="")
				print(colored(righe.rstrip('\n'),'magenta',attrs=['bold']),end="")
				print(colored(" has excessive permission (to \"Authenticated Users\" Group) - it means an attacker impersonating a Domain User OR a Computer Account (e.g. compromising a Computer or Creating a new Computer Account abusing the default \"MS-DS-Machine-Account-Quota\" value) could modify the target file by inserting any malicious payload which would then be potentially executed by the victim." ,'red', attrs=['bold']))

				print("\r")

			if any(s in str(out) for s in string_excessive_permissions_file3):

				print(colored("SMISC2: This remote file: ",'red', attrs=['bold']),end="")
				print(colored(righe.rstrip('\n'),'magenta',attrs=['bold']),end="")
				print(colored(" has excessive permission (to \"Computer Account\" Group) - it means an attacker impersonating a Computer Account (e.g. compromising a Computer or Creating a new Computer Account abusing the default \"MS-DS-Machine-Account-Quota\" value) could modify the target file by inserting any malicious payload which would then be potentially executed by the victim." ,'red', attrs=['bold']))

				print("\r")

def SMISC_4(username, password, domain, ip_address_domain_controller, starting_time, final_time):

	print(colored('\nSMISC4: The Script itself contained inside the SYSVOL / NETLOGON has excessive permission:\n', 'yellow', attrs=['bold', 'underline']))

	current_path = os.getcwd()
	destination_path = current_path + "/scripts_collected/"

	# RegExp that use AWK to generate the file to give to smbcacls
	regexp_awk3 = r'BEGIN{IGNORECASE=1}{s=$0; if (match(s, /(Logon|Logoff|Shutdown|Startup)_/)) {pre=substr(s,1,RSTART+RLENGTH-1); post=substr(s,RSTART+RLENGTH); sub(/-/, "\\", pre); gsub(/_/, "\\", pre); print "\\\\" pre post} else if (match(s, /_scripts_/)) {pre=substr(s,1,RSTART+RLENGTH-1); post=substr(s,RSTART+RLENGTH); sub(/-/, "\\", pre); gsub(/_/, "\\", pre); print "\\\\" pre post} else {pre=s; sub(/-/, "\\", pre); gsub(/_/, "\\", pre); print "\\\\" pre}}'

	cmd = "ls " + destination_path + " | awk " + shlex.quote(regexp_awk3) + " > SMISC4_sysvol_netlogon_script_path_extrapolated.txt"
	#print(cmd)
	os.system(cmd)

	# RegExp that use AWK to generate the final file to give to smbcacls
	regexp_awk3 = r'{l=$0; sub(/^\\\\/,"//",l); n=split(l,a,/\\/); printf "%s/%s ",a[1],a[2]; for(i=3;i<=n;i++) printf i<n?a[i]"/":a[i]; print ""}'

	cmd = "awk " + shlex.quote(regexp_awk3) + " SMISC4_sysvol_netlogon_script_path_extrapolated.txt > SMISC4_for_smbcacls.txt"
	#print(cmd)
	os.system(cmd)

	# Do the smbcacls checks"

	with open("SMISC4_for_smbcacls.txt", "r", encoding="utf-8") as file:

		for righe in file:

			full_username = domain + "\\\\" + username
			cmd = ("smbcacls " + str(righe).rstrip('\n') + " -U " + full_username + " --password " + password)
			#print(cmd)

			result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

			dom_splitted3 = domain.split('.')[0] ## It retrieve the "domain" input, like "MARVEL.local", "IT.MARVEL.local" or "SUB.IT.MARVEL.local" and extrapulate only the "current" domain, so: "MARVEL", "IT" or "SUB"; this is the syntax that wants SMBCacls in some entries. (with this syntax it will works also targetting DC that host a Child Domain)

			stringhe_da_cercare1 = [
			r"ACL:Everyone:ALLOWED/0x0/FULL", # Everyone - FullControl
			r"ACL:Everyone:ALLOWED/I/FULL", # Everyone - Same as above but this permission is inherited (indicated by 'I') from the hierarchical structure of the containing folder
			r"ACL:Everyone:ALLOWED/0x0/RW", # Everyone - Read & Write (since the check is "contains" and not "exact match", this reg will match also for "RWXD" (Modify, Read & Execute, Read, Write) & "RWX" (Read & Execute, Read, Write)
			r"ACL:Everyone:ALLOWED/I/RW", # Everyone - Same as above but this permission is inherited (indicated by 'I') from the hierarchical structure of the containing folder
			rf"ACL:{dom_splitted3}\Domain Users:ALLOWED/0x0/FULL", # Domain Users - FullControl
			rf"ACL:{dom_splitted3}\Domain Users:ALLOWED/I/FULL", # Domain Users - Same as above but this permission is inherited (indicated by 'I') from the hierarchical structure of the containing folder
			rf"ACL:{dom_splitted3}\Domain Users:ALLOWED/0x0/RW", # Domain Users - Read & Write (since the check is "contains" and not "exact match", this reg will match also for "RWXD" (Modify, Read & Execute, Read, Write) & "RWX" (Read & Execute, Read, Write)
			rf"ACL:{dom_splitted3}\Domain Users:ALLOWED/I/RW", # Domain Users - Same as above but this permission is inherited (indicated by 'I') from the hierarchical structure of the containing folder
			]

			stringhe_da_cercare2 = [
			r"ACL:NT AUTHORITY\Authenticated Users:ALLOWED/0x0/FULL", # Authenticated Users FullControl
			r"ACL:NT AUTHORITY\Authenticated Users:ALLOWED/I/FULL",  # Authenticated Users - Same as above but this permission is inherited (indicated by 'I') from the hierarchical structure of the containing folder
			r"ACL:NT AUTHORITY\Authenticated Users:ALLOWED/0x0/RW", # Authenticated Users - Read & Write (since the check is "contains" and not "exact match", this reg will match also for "RWXD" (Modify, Read & Execute, Read, Write) & "RWX" (Read & Execute, Read, Write)
			r"ACL:NT AUTHORITY\Authenticated Users:ALLOWED/I/RW" # Authenticated Users - Same as above but this permission is inherited (indicated by 'I') from the hierarchical structure of the containing folder
			]

			stringhe_da_cercare3 = [
			rf"ACL:{dom_splitted3}\Domain Computers:ALLOWED/0x0/FULL", # Domain Computer Users FullControl
			rf"ACL:{dom_splitted3}\Domain Computers:ALLOWED/I/FULL",  # Domain Computer - Same as above but this permission is inherited (indicated by 'I') from the hierarchical structure of the containing folder
			rf"ACL:{dom_splitted3}\Domain Computers:ALLOWED/0x0/RW", # Domain Computer - Read & Write (since the check is "contains" and not "exact match", this reg will match also for "RWXD" (Modify, Read & Execute, Read, Write) & "RWX" (Read & Execute, Read, Write)
			rf"ACL:{dom_splitted3}\Domain Computers:ALLOWED/I/RW" # Domain Computer - Same as above but this permission is inherited (indicated by 'I') from the hierarchical structure of the containing folder
			]

			if result.returncode != 0:
				#print("Error during the execution of smbcacls: " + str(cmd) + " : " + str(result.stderr))
				continue

			out = result.stdout

			if any(s in str(out) for s in stringhe_da_cercare1):

				print(colored("The automation script itself stored in the SYSVOL/NETLOGON share on the Domain Controller has overly permissive access rights (at \"Everyone\" Group OR \"Domain Users\" Users Group): ",'red', attrs=['bold']),end="")
				print(colored(righe.rstrip('\n'),'magenta',attrs=['bold']),end="")
				print(colored(" - it means an attacker impersonating a Domain User could directly modify this script by inserting any malicious payload which could then be executed by the victim.\n",'red', attrs=['bold']),end="")

				# Logic for the Scheduled Task
				cmd_grep = ("grep -l --color=always \"" + righe.rstrip('\n').rsplit('/', 1)[-1] + "\"" +  " ./ScheduledTaskConf_collected/*") # Do a grep of the LogonScript file in order to verify if it's inside some ScheduledTask configuration
				#print(cmd_grep)
				result1 = subprocess.run(cmd_grep, shell=True, capture_output=True, text=True)
				out1 = (result1.stdout or "").strip() # if the grep command has an output (it means it inside a ScheduledTask)
				if out1:
				    print(colored("Specifically, this script is used within the following Scheduled Task, and by inspecting it, you can determine the execution logic and which user will execute it: ",'red', attrs=['bold']),end="")
				    print(out1, end="") # Print the output of the "grep" command
				else:  # if the grep command does NOT have an output (it means it's NOT inside a ScheduledTask, so if used it's probably done using the "ScriptPath" property)
					print(colored("This script is likely used within the \"ScriptPath\" property of a Domain User object.",'red', attrs=['bold']))
				   
				print("\n")

			if any(s in str(out) for s in stringhe_da_cercare2):

				print(colored("The automation script itself stored in the SYSVOL/NETLOGON share on the Domain Controller has overly permissive access rights (to \"Authenticated Users\" Group): ",'red', attrs=['bold']),end="")
				print(colored(righe.rstrip('\n'),'magenta',attrs=['bold']),end="")
				print(colored(" - it means an attacker impersonating a Domain User OR a Computer Account (e.g. compromising a Computer or Creating a new Computer Account abusing the default \"MS-DS-Machine-Account-Quota\" value) could directly modify this script by inserting any malicious payload which could then be executed by the victim.\n",'red', attrs=['bold']),end="")

				# Logic for the Scheduled Task
				cmd_grep = ("grep -l --color=always \"" + righe.rstrip('\n').rsplit('/', 1)[-1] + "\"" +  " ./ScheduledTaskConf_collected/*") # Do a grep of the LogonScript file in order to verify if it's inside some ScheduledTask configuration
				#print(cmd_grep)
				result1 = subprocess.run(cmd_grep, shell=True, capture_output=True, text=True)
				out1 = (result1.stdout or "").strip() # if the grep command has an output (it means it inside a ScheduledTask)
				if out1:
				    print(colored("Specifically, this script is used within the following Scheduled Task, and by inspecting it, you can determine the execution logic and which user will execute it: ",'red', attrs=['bold']),end="")
				    print(out1, end="") # Print the output of the "grep" command
				else:  # if the grep command does NOT have an output (it means it's NOT inside a ScheduledTask, so if used it's probably done using the "ScriptPath" property)
					print(colored("This script is likely used within the \"ScriptPath\" property of a Domain User object.",'red', attrs=['bold']))
				   
				print("\n")


			if any(s in str(out) for s in stringhe_da_cercare3):

				print(colored("The automation script itself stored in the SYSVOL/NETLOGON share on the Domain Controller has overly permissive access rights (to \"Computer Account\" Group): ",'red', attrs=['bold']),end="")
				print(colored(righe.rstrip('\n'),'magenta',attrs=['bold']),end="")
				print(colored(" - it means an attacker impersonating a Computer Account (e.g. compromising a Computer or Creating a new Computer Account abusing the default \"MS-DS-Machine-Account-Quota\" value) could directly modify this script by inserting any malicious payload which could then be executed by the victim.\n",'red', attrs=['bold']),end="")

				# Logic for the Scheduled Task
				cmd_grep = ("grep -l --color=always \"" + righe.rstrip('\n').rsplit('/', 1)[-1] + "\"" +  " ./ScheduledTaskConf_collected/*") # Do a grep of the LogonScript file in order to verify if it's inside some ScheduledTask configuration
				#print(cmd_grep)
				result1 = subprocess.run(cmd_grep, shell=True, capture_output=True, text=True)
				out1 = (result1.stdout or "").strip() # if the grep command has an output (it means it inside a ScheduledTask)
				if out1:
				    print(colored("Specifically, this script is used within the following Scheduled Task, and by inspecting it, you can determine the execution logic and which user will execute it: ",'red', attrs=['bold']),end="")
				    print(out1, end="") # Print the output of the "grep" command
				else:  # if the grep command does NOT have an output (it means it's NOT inside a ScheduledTask, so if used it's probably done using the "ScriptPath" property)
					print(colored("This script is likely used within the \"ScriptPath\" property of a Domain User object.",'red', attrs=['bold']))
				   
				print("\n")

def SMISC_5(domain, ip_address_domain_controller, starting_time, final_time):

	print(colored('\nSMISC5: Find a Script that Map SMB Share & / OR execute a remote file hosted on a SMB Share - where the machine that expose that SMB share does not exist anymore:\n', 'yellow', attrs=['bold', 'underline']))

	print("Note: If misconfiguration SMISC5 is detected, you can verify if the script vulnerable to SMISC5 is executed through a Scheduled Task or not by checking whether the script is referenced in a \"Scheduled Task.xml\" file within the ./ScheduledTaskConf_collected/ folder (you can use the \"grep\" utility).")

	current_path = os.getcwd()
	destination_path = current_path + "/scripts_collected/"
	
	# RegExp that find every UNC Path
	every_unc_regexp = r'("(\\\\\\\\\\?\\UNC\\[A-Za-z0-9._$-]+\\[A-Za-z0-9._$-]+(\\[^"]+)*)")|((\\\\\\\\\\?\\UNC\\[A-Za-z0-9._$-]+\\[A-Za-z0-9._$-]+(\\[^[:space:]"]+)*))|("(\\\\[A-Za-z0-9._$-]+\\[A-Za-z0-9._$-]+(\\[^"]+)*)")|((\\\\[A-Za-z0-9._$-]+\\[A-Za-z0-9._$-]+(\\[^[:space:]"]+)*))'
	
	# Create a temp file 1 called "/script_collected/SMISC5_unc_path_extracted.txt"
	cmd = "grep -E -o " + shlex.quote(every_unc_regexp) + " " + shlex.quote(destination_path) + "* > " + "SMISC5_unc_path_extracted.txt 2>/dev/null"
	#print(cmd)
	os.system(cmd)

	# RegExp that extrapolate hostname from every UNC Path file
	hostname_from_unc_regexp = r'^\\\\\K[^\\]+'

	# Create a temp file 2 called "/SMISC5_list_hostname_indicated_inside_unc.txt"
	cmd = "cat SMISC5_unc_path_extracted.txt | cut -d ':' -f 2 | grep -oP " + shlex.quote(hostname_from_unc_regexp) + " | sort -n | uniq > " + "SMISC5_list_hostname_indicated_inside_unc.txt 2>/dev/null"
	#print(cmd)
	os.system(cmd)

	hostnames = open("SMISC5_list_hostname_indicated_inside_unc.txt", "r")

	for hostname in hostnames:

		hostname = hostname.rstrip("\r\n") # Remove \r\n

		dnsquery = dns.resolver.Resolver(configure=False)
		dnsquery.nameservers = [ip_address_domain_controller]
		#print(hostname + "." + domain)

		try:
		    results = dnsquery.resolve(hostname + "." + domain, 'A') # Execute DNS Query
		    jitter(starting_time,final_time) # Sleep
		except dns.resolver.NXDOMAIN:

		    print(colored("The hostname called " + "\"" + hostname + "\"" + " on the " + "\"" + domain + "\"" + " domain does NOT exist - it means that an attacker could potentially hijack it by registering a malicious DNS record:",'red', attrs=['bold']))
		    cmd = ("cat SMISC5_unc_path_extracted.txt | grep " + hostname)
		    # print(cmd)
		    output = os.popen(cmd).read() # Make the cat output command magenta
		    colored_output = colored(output, 'magenta') # Make the cat output command magenta
		    print(colored_output) # Make the cat output command magenta

# A dynamic sleep function for OPSEC
def jitter(starting_time, final_time):
    time.sleep(random.uniform(starting_time, final_time))

## Start Script
if __name__ == '__main__':
	main()
