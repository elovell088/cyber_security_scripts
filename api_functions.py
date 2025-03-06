#This file contains Palo Alto API Functions -- Written by: Eric Lovell

#Shows base functions for contructing and making Palo Alto API calls via Python

#Run functions will pull new data from a CSV File. CSV file paths are also constructed. Pre-built CSV templates are used and are specific to each function/change.

#Mangled functions below the run functions construct and send the API call using data from the CSV file. These are called and work together with the run functions.

#This will work for any model of Palo Alto Firewalls and Panorama. Variables within functions must be modified for your organizations specific data. 



#Imports
import sys
import pyotp
import keyring
import requests
import json
import csv
import urllib3
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from cryptography.fernet import Fernet


#File Start
csv_start = '<FIRST HALF OF THE CSV FILE PATH>'


#Decryption Functions
#####################################################################################################################################################################################
#####################################################################################################################################################################################
#####################################################################################################################################################################################
def decrypt_api_key():
    """
    Function that decrypts the API Key. CALLS decrypt()
    
    Parameters:
        None
    """

    api_file = '<FILE PATH FOR ENCRYPTED API KEY>'
    decrypted_api = __decrypt(api_file)

    return decrypted_api



def decrypt_totp_key():
    """
    Function that decrypts the TOTP_key. CALLS decrypt()
    
    Parameters:
        None
    """

    run_program = False
    totp_file = '<FILE PATH FOR ENCRYPTED TOTP SECRET>' 
    decrypted_totp = __decrypt(totp_file)

    #MFA Input Prompts
    totp = pyotp.TOTP(decrypted_totp)
    verify_user = input("Enter MFA code: ")

    #TOTP Verification
    if totp.verify(verify_user):
        print("\nAccess granted. Running Script..")
        run_program = True 
    else:
        print("Access Denied.")
        run_program = False 
    
    if not run_program:
        sys.exit()  



def __decrypt(file_path):
    """
    Function that decrypts the API key and TOTP Key to be used for API Scripting. CALLS decrypt_key()
    
    Parameters:
        file_path (String) -- File path of the api and totp key
    """
    
    private_key = __decrypt_private_key()
    private_key = RSA.import_key(private_key)

    with open(file_path, 'rb') as file_name:
        enc_session_key = file_name.read(private_key.size_in_bytes())
        nonce = file_name.read(16)
        tag = file_name.read(16)
        ciphertext = file_name.read()

    #Use the private key to decrypt the session key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    message = cipher_aes.decrypt_and_verify(ciphertext, tag)
    file_info = message.decode("utf-8")

    return file_info



def __decrypt_private_key():
    """
    Function that pulls and decrypts a key stored in Credential Manager - This key is used to decrypt the private key (Private key decrypts API and TOTP key)
    
    Parameters:
        None
    """
    
    #Pulls symmetric key from credential manager
    stored_key = keyring.get_password('<CREDENTIAL MANAGER SERVICE NAME>', '<CREDENTIAL MANAGER USERNAME>')
    cipher_suite = Fernet(stored_key)

    #Pulls private key
    with open('<FILE PATH FOR ENCRYPTED PRIVATE KEY>', 'rb') as file:
        encrypted_key = file.read()

    #Decrypts the private key
    decrypted_key = cipher_suite.decrypt(encrypted_key)

    #Strip whitespace and decode to string
    decrypted_key_str = decrypted_key.strip().decode('utf-8')

    return decrypted_key_str





#REST Functions --- RUN functions pull new data and call function below
#####################################################################################################################################################################################
#####################################################################################################################################################################################
#####################################################################################################################################################################################
def run_address_objects(ticket_number, decrypted_api):
    """
    Function that pulls data from a CSV file and runs create_address_object()
        
    Parameters:
        ticket_number (string) -- Ticket number for the firewall change. Used to create file path for csv location.

        decrypted_api (string) -- API key used to authenticate API calls. Pulled and decrypted in main()
    """

    csv_end = '<LAST HALF OF CSV FILE PATH>'
    csv_file = csv_start + csv_end

    with open(csv_file, mode='r') as csvfile: 
        reader = csv.DictReader(csvfile)
    
        for row in reader:
            ip_address = row['ip_address']
            description = row['description']
            tags = [tag.strip() for tag in row['tags'].split(',')]
            
            __create_address_object(ip_address, description, tags, decrypted_api)


def __create_address_object(object_IP, object_description, tag_name, api_key):
    """
    REST Function that creates an address object
    
    Parameters:
        object_IP (String) -- IP address. This is used for the name and address of the object
        object_description (String) -- Description of the address object
        tag_name (String) -- Tags associated with the address object
        api_key (String) -- This is the api_key (API key is pulled and decrypted in Main)
    """
    
    firewall_URL = "<PANORAMA OR FIREWALL URL>"
    device_group = "<DEVICE GROUP NAME>"

    #Builds URL with query parameters
    query_params = {
    "location": "device-group",
    "name": object_IP,
    "device-group": device_group,
    "input-format": "json",
    "output-format": "json"
    }
    
    #Builds the HTTP headers
    headers = {
    "X-PAN-KEY": api_key,
    "Content-Type": "application/json",
    "Accept": "application/json"
    }

    #Contains payload with address object information
    payload = {
    "entry": [
        {
            "@location": device_group,
            "@name": object_IP,
            "description": object_description,
            "ip-netmask": object_IP,
            "tag": {
                "member": tag_name
                }
            }
        ]
    }
    
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    #POST request with response placed inside a variable 
    response = requests.post(firewall_URL, headers=headers, params=query_params, data=json.dumps(payload), verify=False)

    if response.status_code == 200:
        print("\nAddress object: " + object_IP + " was created successfully.")
        print("Response:", response.json())
        print('\n')
    else:
        print("Request failed.")
        print("Status Code:", response.status_code)
        print("Response:", response.text)


###


def run_address_groups(ticket_number, decrypted_api):
    """
    Function that pulls data from a CSV file and runs create_address_group()
        
    Parameters:
        ticket_number (string) -- Ticket number for the firewall change. Used to create file path for csv location.

        decrypted_api (string) -- API key used to authenticate API calls. Pulled and decrypted in main()
    """

    csv_end = '<LAST HALF OF CSV FILE PATH>'
    csv_file = csv_start + csv_end

    with open(csv_file, mode='r') as csvfile: 
        reader = csv.DictReader(csvfile)
    
        for row in reader:
            group_name = row['group_name']
            description = row['description']
            addresses = [address.strip() for address in row['addresses'].split(',')]
            tags = [tag.strip() for tag in row['tags'].split(',')]
            
            __create_address_groups(group_name, description, addresses, tags, decrypted_api)


def __create_address_groups(group_name, group_description, address, tag_name, api_key):
    """
    REST Function that creates an address group
    
    Parameters:
        group_name (String) -- Name of the address group
        group_description (String) -- Description of the address group
        address (String) -- IP addresses 
        tag_name (String) -- Tags associated with the address group
        api_key (String) -- This is the api_key (API key is pulled and decrypted in Main)
    """
    
    firewall_URL = "<PANORAMA OR FIREWALL URL>"
    device_group = "<DEVICE GROUP NAME>"

    #Builds URL with query parameters
    query_params = {
    "location": "device-group",
    "name": group_name,
    "device-group": device_group,
    "input-format": "json",
    "output-format": "json"
    }
    
    #Builds the HTTP headers
    headers = {
    "X-PAN-KEY": api_key,
    "Content-Type": "application/json",
    "Accept": "application/json"
    }

    #Contains payload with address object information
    payload = {
    "entry": [
        {
            "@location": device_group,
            "@name": group_name,
            "description": group_description,
            "static": {
                "member" : address
                },
            "tag": {
                "member": tag_name
                }
            }
        ]
    }
    
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    #POST request with response placed inside a variable 
    response = requests.post(firewall_URL, headers=headers, params=query_params, data=json.dumps(payload), verify=False)

    if response.status_code == 200:
        print("\nAddress group: " + group_name + " was created successfully.")
        print("Response:", response.json())
        print('\n')
    else:
        print("Request failed.")
        print("Status Code:", response.status_code)
        print("Response:", response.text)


###


def run_service_objects(ticket_number, decrypted_api):
    """
    Function that pulls data from a CSV file and runs create_service_object function
        
    Parameters:
        ticket_number (string) -- Ticket number for the firewall change. Used to create file path for csv location.

        decrypted_api (string) -- API key used to authenticate API calls. Pulled and decrypted in main()
    """
    csv_end = '<LAST HALF OF CSV FILE PATH>'
    csv_file = csv_start + csv_end

    with open(csv_file, mode='r') as csvfile:
        reader = csv.DictReader(csvfile)
    
        for row in reader:
            service_name = row['service_name']
            protocol = row['protocol']
            port = row['port']
            
            __create_service_object(service_name, protocol, port, decrypted_api)


def __create_service_object(service_name, protocol, port, api_key):
    """
    REST Function that creates a service object 

    Parameters:
        service_name (String) -- Name of the service object
        protocol (String) -- Protocol type (TCP, UDP, etc.)
        port (String) -- Destination port of the service object
        api_key (String) -- This is the api_key (API key is pulled and decrypted in Main)
    """
    
    firewall_URL = "<PANORAMA OR FIREWALL URL>"
    device_group = "<DEVICE GROUP NAME>"

    #Builds URL with query parameters
    query_params = {
    "location": "device-group",
    "name": service_name,
    "device-group": device_group,
    "input-format": "json",
    "output-format": "json"
    }
    
    #Builds the HTTP headers
    headers = {
    "X-PAN-KEY": api_key,
    "Content-Type": "application/json",
    "Accept": "application/json"
    }

    #Contains payload with address object information
    payload = {
    "entry": [
        {
            "@location": device_group,
            "@name": service_name,
            "protocol": {
                protocol : {
                    "port" : port
                    }
                }
            }
        ]
    }
    
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    #POST request with response placed inside a variable 
    response = requests.post(firewall_URL, headers=headers, params=query_params, data=json.dumps(payload), verify=False)

    if response.status_code == 200:
        print("\nService object: " + service_name + " was created successfully.")
        print("Response:", response.json())
        print('\n')
    else:
        print("Request failed.")
        print("Status Code:", response.status_code)
        print("Response:", response.text)


###


def run_service_groups(ticket_number, decrypted_api):
    """
    Function that pulls data from a CSV file and runs create_service_group()
        
    Parameters:
        ticket_number (string) -- Ticket number for the firewall change. Used to create file path for csv location.

        decrypted_api (string) -- API key used to authenticate API calls. Pulled and decrypted in main()
    """

    csv_end = '<LAST HALF OF CSV FILE PATH>'
    csv_file = csv_start + csv_end

    with open(csv_file, mode='r') as csvfile:
        reader = csv.DictReader(csvfile)
    
        for row in reader:
            group_name = row['group_name']
            services = [service.strip() for service in row['services'].split(',')]
            tags = [tag.strip() for tag in row['tags'].split(',')]
            
            __create_service_group(group_name, services, tags, decrypted_api)


def __create_service_group(group_name, services, tag_name, api_key):
    """
    REST Function that creates a service group

    Parameters:
        group_name (String) -- Name of the service group
        services (String) -- Services that are added to the group (TCP 3389, UDP 123, etc.)
        tag_name (String) -- Tags to associate with the service group
        api_key (String) -- This is the api_key (API key is pulled and decrypted in Main)
    """
    
    firewall_URL = "<PANORAMA OR FIREWALL URL>"
    device_group = "<DEVICE GROUP NAME>"

    #Builds URL with query parameters
    query_params = {
    "location": "device-group",
    "name": group_name,
    "device-group": device_group,
    "input-format": "json",
    "output-format": "json"
    }
    
    #Builds the HTTP headers
    headers = {
    "X-PAN-KEY": api_key,
    "Content-Type": "application/json",
    "Accept": "application/json"
    }

    #Contains payload with address object information
    payload = {
    "entry": [
        {
            "@location": device_group,
            "@name": group_name,
            "members": {
                "member" : services
            },
            "tag": {
                "member": tag_name
                }
            }
        ]
    }
    
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    #POST request with response placed inside a variable 
    response = requests.post(firewall_URL, headers=headers, params=query_params, data=json.dumps(payload), verify=False)

    if response.status_code == 200:
        print("\nService group: " + group_name + " was created successfully.")
        print("Response:", response.json())
        print('\n')
    else:
        print("Request failed.")
        print("Status Code:", response.status_code)
        print("Response:", response.text)


###


def run_application_object(ticket_number, decrypted_api):
    """
    Function that pulls data from a CSV file and runs create_application_object()
        
    Parameters:
        ticket_number (string) -- Ticket number for the firewall change. Used to create file path for csv location.

        decrypted_api (string) -- API key used to authenticate API calls. Pulled and decrypted in main()
    """
    csv_end = '<LAST HALF OF CSV FILE PATH>'
    csv_file = csv_start + csv_end

    with open(csv_file, mode='r') as csvfile:
        reader = csv.DictReader(csvfile)

        for row in reader:
                app_name = row['app_name']
                description = row['description']
                category = row['category']
                subcategory = row['subcategory']
                technology = row['technology']
                risk = row['risk']
                port = row['port']
                sig_name = row['sig_name']
                sig_comment = row['sig_comment']
                and_name = row['and_name']
                or_name = row['or_name']
                operator = row['operator']
                pattern_context = row['pattern_context']
                pattern = row['pattern']

                __create_application_object(app_name, description, category, subcategory, technology, risk, port, sig_name, sig_comment, and_name, or_name, operator, pattern_context, pattern, decrypted_api)


def __create_application_object(app_name,description,category,subcategory,technology,risk,port,sig_name,sig_comment,and_name,or_name,operator,pattern_context,pattern,api_key):
    """
    REST Function that creates a custom application object

    Parameters:
        app_name (String) -- Name of the custom application
        description (String) -- Description of the application
        category (String) -- The category that this application belongs too (business-systems, networking, etc.)
        subcategory (String) -- The subcategory this application belongs too (auth-service, file-sharing, etc.)
        technology (String) -- Type of technology (brower-based, client-server, etc.)
        risk (String) -- Risk associated with the application (1-5 value)
        port (String) -- Ports that the application use
        sig_name (String) -- Name of the application signature
        sig_comment (String) -- Description of the application signature
        and_name (String) -- and condition for signature matching 
        or_name (String) -- or condition for signature matching
        operator (String) -- Pattern that the conditions will match too (Pattern Match, Greater than, Less than, etc.)
        pattern_context (String) -- Signature location within the payload (http-req-headers, http-req-uri, etc.)
        pattern (String) -- String value of the signature
        api_key (String) -- This is the api_key (API key is pulled and decrypted in Main)
    """
    
    firewall_URL = "<PANORAMA OR FIREWALL URL>"
    device_group = "<DEVICE GROUP NAME>"

    #Builds URL with query parameters
    query_params = {
    "location": "device-group",
    "name": app_name,
    "device-group": device_group,
    "input-format": "json",
    "output-format": "json"
    }
    
    #Builds the HTTP headers
    headers = {
    "X-PAN-KEY": api_key,
    "Content-Type": "application/json",
    "Accept": "application/json"
    }

    #Contains payload with address object information
    payload = {
    "entry": 
        {
            "@name" : app_name,
            "category" : category,
            "subcategory" : subcategory,
            "technology" : technology,
            "risk" : risk,
            "description" : description,
            "default" : {
                "port" : {
                    "member" :[
                        port
                    ]
                }
            },
            "signature" : {        
                "entry" : [
                    {
                        "@name" : sig_name,
                        "comment" : sig_comment,
                        "and-condition" :{
                            "entry" : [
                                {
                                    "@name" : and_name,
                                    "or-condition" : {
                                        "entry" : [
                                            {
                                                "@name" : or_name,
                                                "operator" : {
                                                    operator :{
                                                    "context" : pattern_context,
                                                    "pattern" : pattern,
                                                    }
                                                }
                                            }
                                        ]
                                    }
                                }
                            ]
                        }

                        }

                    ]
                }

            }
        
    }
    
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    #POST request with response placed inside a variable 
    response = requests.post(firewall_URL, headers=headers, params=query_params, data=json.dumps(payload), verify=False)

    if response.status_code == 200:
        print("\nApplication: " + app_name + " was created successfully.")
        print("Response:", response.json())
        print('\n')
    else:
        print("Request failed.")
        print("Status Code:", response.status_code)
        print("Response:", response.text)


###


def run_application_groups(ticket_number, decrypted_api):
    """
    Function that pulls data from a CSV file and runs create_application_group()
        
    Parameters:
        ticket_number (string) -- Ticket number for the firewall change. Used to create file path for csv location.

        decrypted_api (string) -- API key used to authenticate API calls. Pulled and decrypted in main()
    """

    csv_end = '<LAST HALF OF CSV FILE PATH>'
    csv_file = csv_start + csv_end

    with open(csv_file, mode='r') as csvfile:
        reader = csv.DictReader(csvfile)
    
        for row in reader:
            group_name = row['group_name']
            services = [service.strip() for service in row['applications'].split(',')]
            
            __create_application_group(group_name, services, decrypted_api)


def __create_application_group(group_name, applications, api_key):
    """
    REST Function that creates an application group
    
    Parameters:
        group_name (String) -- Name of the application group
        applications (String) -- List of applications
        api_key (String) -- This is the api_key (API key is pulled and decrypted in Main)
    """
    
    firewall_URL = "<PANORAMA OR FIREWALL URL>"
    device_group = "<DEVICE GROUP NAME>"

    #Builds URL with query parameters
    query_params = {
    "location": "device-group",
    "name": group_name,
    "device-group": device_group,
    "input-format": "json",
    "output-format": "json"
    }
    
    #Builds the HTTP headers
    headers = {
    "X-PAN-KEY": api_key,
    "Content-Type": "application/json",
    "Accept": "application/json"
    }

    #Contains payload with address object information
    payload = {
        "entry" : {
            "@name" : group_name,
            "members" : {
                "member" : applications
            }
        }
    }
    

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    #POST request with response placed inside a variable 
    response = requests.post(firewall_URL, headers=headers, params=query_params, data=json.dumps(payload), verify=False)

    if response.status_code == 200:
        print("\nApplication group: " + group_name + " was created successfully.")
        print("Response:", response.json())
        print('\n')
    else:
        print("Request failed.")
        print("Status Code:", response.status_code)
        print("Response:", response.text)


###


def run_security_policies(ticket_number, decrypted_api):
    """
    Function that pulls data from a CSV file and runs create_security_policy()
        
    Parameters:
        ticket_number (string) -- Ticket number for the firewall change. Used to create file path for csv location.

        decrypted_api (string) -- API key used to authenticate API calls. Pulled and decrypted in main()
    """  

    csv_end = '<LAST HALF OF CSV FILE PATH>'
    csv_file = csv_start + csv_end

    with open(csv_file, mode='r') as csvfile:
        reader = csv.DictReader(csvfile)
    
        for row in reader:
            device_group = row['device_group']
            rule_name = row['rule_name']
            rule_type = row['rule_type']
            rule_description = row['rule_description']
            action = row['action']
            source_zone = row['source_zone']
            dest_zone = row['dest_zone']
            group_profile = row['group_profile']
            tags = [tag.strip() for tag in row['tags'].split(',')]
            source_ip = [ip.strip() for ip in row['source_ip'].split(',')]
            dest_ip = [ip.strip() for ip in row['dest_ip'].split(',')]
            apps = [app.strip() for app in row['apps'].split(',')]
            services = [service.strip() for service in row['services'].split(',')]
            source_user = [user.strip() for user in row['source_user'].split(',')]
            
            __create_security_policy(decrypted_api, device_group, rule_name, rule_type, rule_description, action, source_zone, dest_zone, group_profile, tags, source_ip, dest_ip, apps, services, source_user)
            set_audit_comment(device_group, rule_name, ticket_number, decrypted_api)


def __create_security_policy(api_key,device_group,rule_name,rule_type,rule_description,action,source_zone,dest_zone,group_profile,tags,source_ip,dest_ip,apps,services,source_user):
    """
    REST Function to create a security policy

    Parameters:
        api_key (String) -- This is the api_key (API key is pulled and decrypted in Main)
        device_group (String) -- Device group location. Security rules are placed in different locations via Panorama (Perimeter, Datacenter, etc.)
        rule_name (String) -- This is the name of the security policy
        rule_type (String) -- Type of rule. This is typcially 'universal'
        rule_description (String) -- Description of the security rule
        action (String) -- This is the action of the security rule (allow, deny, drop, etc)
        source_zone (String) -- The source zone of the security policy
        dest_zone (String) -- The destination zone of the security policy
        group_profile (String) -- Name of the security profile group assigned to the security policy
        tags (String) -- Tag or list of tags associated with the security rule
        source_ip (String) -- Source IP address
        dest_ip (String) -- Destination IP address
        apps (String) -- Application or list of applications assigned to a security rule (SSL, DNS, etc.)
        services (String) -- Service or list of services assigned to a security rule (TCP 3389, UDP 123. etc.)
        source_user (String) -- The users the security policy applies too. Specifiy a user name or set to 'any' if it applies to any user
    """


    firewall_URL = "<PANORAMA OR FIREWALL URL>"

    #Buuilds the URL 
    query_params = {
    "location": "device-group",
    "name": rule_name,
    "device-group": device_group,
    "input-format": "json",
    "output-format": "json",
    }
    
    #Builds the http header
    headers = {
    "X-PAN-KEY": api_key,
    "Content-Type": "application/json",
    "Accept": "application/json"
    }
    #Builds the payload
    payload = {
    "entry": [
        {
            "@location": device_group,
            "@name": rule_name,
            "rule-type": rule_type,
            "description": rule_description,
            "action": action,
            "log-setting": "Send to Panorama",
            "log-end": "yes",
            "tag": {
                "member": tags
            },
            "from": {
                "member":[
                    source_zone
                ]
            },
            "source": {
                "member": source_ip
            },
            "source-user": {
                "member": source_user
            },
            "to": {
                "member": [
                    dest_zone
                ]
            },
            "destination": {
                "member": dest_ip
            },
            "application": {
                "member": apps
            },
            "service": {
                "member": services
            },
            "profile-setting": {
                "group": {
                    "member": [group_profile]
                }
            }
        }
    ]
}
    
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    response = requests.post(firewall_URL, headers=headers, params=query_params, data=json.dumps(payload), verify=False)


    if response.status_code == 200:
        print("\nSecurity Policy: " + rule_name + " was created successfully!")
        print("Response:", response.json())
        print('\n')
    else:
        print("Request failed.")
        print("Status Code:", response.status_code)
        print("Response:", response.text)


###


def run_move_security_policies(ticket_number, decrypted_api):
    """
    Function that pulls data from a CSV file and runs move_security_policy()
        
    Parameters:
        ticket_number (string) -- Ticket number for the firewall change. Used to create file path for csv location.

        decrypted_api (string) -- API key used to authenticate API calls. Pulled and decrypted in main()
    """      
    move_end = '<LAST HALF OF CSV FILE PATH>'
    move_file = csv_start + csv_end

    with open(move_file, mode='r') as csvfile:
        reader = csv.DictReader(csvfile)
    
        for row in reader:
            rule_name = row['rule_name']
            device_group = row['device_group']
            target = row['target']

            __move_security_policy(decrypted_api, rule_name, device_group, target)


def __move_security_policy(api_key, rule_name, device_group, target):
    """
    REST Function that moves a security policy to a different position in the policy table

    Parameters:
        api_key (String) -- This is the api_key (API key is pulled and decrypted in Main)
        rule_name (String) -- Name of the security policy
        device_group (String) -- Device group location. Security rules are placed in different locations via Panorama (Perimeter, Datacenter, etc.)
        target (String) -- Name of the rule to place above. Ex. - rule_name is placed above this rule.
    """
    
    move_URL = "<PANORAMA OR FIREWALL URL>"

    #Builds URL with query parameters
    query_params = {
    "location": "device-group",
    "name": rule_name,
    "device-group": device_group,
    "where" : "before",
    "dst" : target,
    "output-format": "json"
    }
    
    #Builds the HTTP headers
    headers = {
    "X-PAN-KEY": api_key,
    "Content-Type": "application/json",
    "Accept": "application/json"
    }

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    #POST request with response placed inside a variable 
    response = requests.post(move_URL, headers=headers, params=query_params)

    if response.status_code == 200:
        print("\n" + rule_name + " was moved successfully!")
        print("Response:", response.json())
        print('\n')
    else:
        print("Request failed.")
        print("Status Code:", response.status_code)
        print("Response:", response.text)


###


def run_nat_policies(ticket_number, decrypted_api):
    """
    Function that pulls data from a CSV file and runs create_nat_policy()
        
    Parameters:
        ticket_number (string) -- Ticket number for the firewall change. Used to create file path for csv location.

        decrypted_api (string) -- API key used to authenticate API calls. Pulled and decrypted in main()
    """      

    csv_end = '<LAST HALF OF CSV FILE PATH>'
    csv_file = csv_start + csv_end
    device_group = "<DEVICE GROUP NAME>"

    with open(csv_file, mode='r') as csvfile:
        reader = csv.DictReader(csvfile)
    
        for row in reader:
            rule_name = row['rule_name']
            description = row['description']
            tags = [tag.strip() for tag in row['tags'].split(',')]
            source_zone = row['source_zone']
            destination_zone = row['destination_zone']
            source_ip = [ip.strip() for ip in row['source_ip'].split(',')]
            destination_ip = [ip.strip() for ip in row['destination_ip'].split(',')]
            services = [service.strip() for service in row['services'].split(',')]
            public_ip = row['public_ip']
            direction = row['direction']
            
            
            __create_nat_policy(rule_name, description, tags, source_zone, destination_zone, source_ip, destination_ip, services, public_ip, direction, decrypted_api)


def __create_nat_policy(rule_name, description, tags, source_zone, destination_zone, source_ip, destination_ip, services, public_ip, direction, api_key):
    """
    REST Function that creates a NAT Policy rule 

    Parameters:
        rule_name (String) -- Name of the NAT rule
        description (String) -- Description of the NAT rule
        tags (String) -- Tags associated with the NAT rule
        source_zone (String) -- Source zone of the NAT rule
        destination_zone (String) -- Destination zone of the NAT rule
        source_IP (String) -- Source IP Address
        destination_IP (String) -- Destination IP Address
        services (String) -- Service or list of services assigned to a security rule (TCP 3389, UDP 123. etc.)
        public_ip (String) -- Public IP that the private IP will be mapped to
        direction (String) -- Direction of the IP mapping (bi-directional)
        api_key (String) -- This is the api_key (API key is pulled and decrypted in Main)
    """
    
    firewall_URL = "<PANORAMA OR FIREWALL URL>"
    device_group = "<DEVICE GROUP NAME>"

    #Builds URL with query parameters
    query_params = {
    "location": "device-group",
    "name": rule_name,
    "device-group": device_group,
    "input-format": "json",
    "output-format": "json"
    }
    
    #Builds the HTTP headers
    headers = {
    "X-PAN-KEY": api_key,
    "Content-Type": "application/json",
    "Accept": "application/json"
    }

    #Contains payload with address object information
    payload = {
    "entry": [
        {
            "@location": device_group,
            "@name": rule_name,
            "description" : description,
            "tag" : {
                "member" : tags
            },
            "from" : {
                "member" : source_zone
            },
            "to" : {
                "member" : destination_zone
            },
            "source" : {
                "member" : source_ip
            },
            "destination" : {
                "member" : destination_ip
            },
            "service" : services,
            "source-translation" :{
                "static-ip" : {
                    "translated-address" : public_ip,
                    "bi-directional" : direction
                }
            }
            }
        ]
    }
    
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    #POST request with response placed inside a variable 
    response = requests.post(firewall_URL, headers=headers, params=query_params, data=json.dumps(payload), verify=False)

    if response.status_code == 200:
        print("\nNAT Rule: " + rule_name + " was created successfully.")
        print("Response:", response.json())
        print('\n')
    else:
        print("Request failed.")
        print("Status Code:", response.status_code)
        print("Response:", response.text)


###


def run_move_nat_policies(ticket_number, decrypted_api):
    """
    Function that pulls data from a CSV file and runs move_security_policy()
        
    Parameters:
        ticket_number (string) -- Ticket number for the firewall change. Used to create file path for csv location.

        decrypted_api (string) -- API key used to authenticate API calls. Pulled and decrypted in main()
    """  

    move_end = '<LAST HALF OF CSV FILE PATH>'
    move_file = csv_start + csv_end

    with open(move_file, mode='r') as csvfile:
        reader = csv.DictReader(csvfile)
    
        for row in reader:
            rule_name = row['rule_name']
            device_group = row['device_group']
            target = row['target']

            __move_nat_policy(decrypted_api, rule_name, device_group, target)


def __move_nat_policy(api_key, rule_name, device_group, target):
    """
    REST Function that moves a NAT policy to a different position in the policy table

    Parameters:
        api_key (String) -- This is the api_key (API key is pulled and decrypted in Main)
        rule_name (String) -- Name of the NAT policy
        device_group (String) -- Device group location. Security rules are placed in different locations via Panorama (Perimeter, Datacenter, etc.)
        target (String) -- Name of the rule to place above. rule_name is placed above this rule.
    """
    
    move_URL = "<PANORAMA OR FIREWALL URL>"

    #Builds URL with query parameters
    query_params = {
    "location": "device-group",
    "name": rule_name,
    "device-group": device_group,
    "where" : "before",
    "dst" : target,
    "output-format": "json"
    }
    
    #Builds the HTTP headers
    headers = {
    "X-PAN-KEY": api_key,
    "Content-Type": "application/json",
    "Accept": "application/json"
    }

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    #POST request with response placed inside a variable 
    response = requests.post(move_URL, headers=headers, params=query_params)

    if response.status_code == 200:
        print("\n" + rule_name + " was moved successfully!")
        print("Response:", response.json())
        print('\n')
    else:
        print("Request failed.")
        print("Status Code:", response.status_code)
        print("Response:", response.text)


###


def run_modify_nat(ticket_number, decrypted_api):
    """
    Function that pulls data from a CSV file and runs modify_nat_rule()
        
    Parameters:
        ticket_number (string) -- Ticket number for the firewall change. Used to create file path for csv location.

        decrypted_api (string) -- API key used to authenticate API calls. Pulled and decrypted in main()
    """  

    csv_end = '<LAST HALF OF CSV FILE PATH>'
    csv_file = csv_start + csv_end

    with open(csv_file, mode='r') as csvfile:
        reader = csv.DictReader(csvfile)
    
        for row in reader:
            rule_name = row['rule_name']
            source_zone = row['source_zone']
            destination_zone = row['destination_zone']
            source_ip = row['source_ip']
            destination_ip = row['destination_ip']
            service = row['services']
            tags = [tag.strip() for tag in row['tags'].split(',')]
            status = row['disabled']
            public_ip = row['public_ip']
            direction = row['direction']
            

            __modify_nat_rule(rule_name, source_zone, destination_zone, source_ip, destination_ip, service, tags, status, public_ip, direction, decrypted_api)


def __modify_nat_rule(rule_name, source_zone, destination_zone, source_ip, destination_ip, service, tags, status, public_ip, direction, api_key):
    """
    Function that allows modification to all elements of a NAT policy

    Parameters:
        rule_name (String) -- This is the name of the NAT policy
        source_zone (String) -- The source zone of the security policy
        destination_zone (String) -- The destination zone of the security policy
        source_ip (String) -- Source IP address
        destination_ip (String) -- Destination IP address
        service (String) -- Service or list of services assigned to a security rule (TCP 3389, UDP 123. etc.)
        tags (String) -- Tag or list of tags associated with the security rule
        status (String) -- To disable rule set this to 'yes'. To enable the rule set this to 'no'
        public_ip (String) -- Public IP that the private IP will be mapped to
        direction (String) -- Direction of the IP mapping (bi-directional)
        api_key (String) -- This is the api_key (API key is pulled and decrypted in Main)
    """
    
    firewall_URL = "<PANORAMA OR FIREWALL URL>"
    device_group = "<DEVICE GROUP NAME>"

    #Builds URL with query parameters
    query_params = {
    "location": "device-group",
    "name": rule_name,
    "device-group": device_group,
    "input-format": "json",
    "output-format": "json"
    }
    
    #Builds the HTTP headers
    headers = {
    "X-PAN-KEY": api_key,
    "Content-Type": "application/json",
    "Accept": "application/json"
    }

    #Contains payload with address object information
    payload = {
    "entry": [
        {
            "@location": device_group,
            "@name": rule_name,
            "from": {
                "member" : source_zone
            },
            "to": {
                "member" : destination_zone
            },
            "source": {
                "member" : source_ip
            },
            "destination": {
                "member" : destination_ip
            },
            "service": service,
            "tag": {
                "member": tags
                },
            "disabled" : status, #'yes' or 'no'
            "source-translation" : {
                "static-ip" : {
                    "translated-address" : public_ip,
                    "bi-directional" : direction
                }
            }

            }
        ]
    }
    
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    #POST request with response placed inside a variable 
    response = requests.put(firewall_URL, headers=headers, params=query_params, data=json.dumps(payload), verify=False)

    if response.status_code == 200:
        print("\nNAT Rule: " + rule_name + " was modified successfully.")
        print("Response:", response.json())
        print('\n')
    else:
        print("Request failed.")
        print("Status Code:", response.status_code)
        print("Response:", response.text)


###


def run_modify_address(ticket_number, decrypted_api):
    """
    Function that pulls data from a CSV file and runs modify_address_object()
        
    Parameters:
        ticket_number (string) -- Ticket number for the firewall change. Used to create file path for csv location.

        decrypted_api (string) -- API key used to authenticate API calls. Pulled and decrypted in main()
    """  

    csv_end = '<LAST HALF OF CSV FILE PATH>'
    csv_file = csv_start + csv_end

    with open(csv_file, mode='r') as csvfile:
        reader = csv.DictReader(csvfile)
    
        for row in reader:
            address_name = row['address_name']
            ip_address = row['ip_address']
            description = row['description']
            tags = [tag.strip() for tag in row['tags'].split(',')]
            

            __modify_address_object(address_name, ip_address, description, tags, decrypted_api)


def __modify_address_object(address_name, ip_address, description, tags, api_key):
    """
    Function that modifies the name, ip, desription, and tags of an address object

    Parameters:
        address_name (String) -- Name of the address object
        ip_address (String) -- IP of the address object
        description (String) -- Description of the address object
        tags (String) -- Tags associated with the address object
        api_key (String) -- This is the api_key (API key is pulled and decrypted in Main)
    """
    
    firewall_URL = "PANORAMA OR FIREWALL URL"
    device_group = "<DEVICE GROUP NAME>"

    #Builds URL with query parameters
    query_params = {
    "location": "device-group",
    "name": address_name,
    "device-group": device_group,
    "input-format": "json",
    "output-format": "json"
    }
    
    #Builds the HTTP headers
    headers = {
    "X-PAN-KEY": api_key,
    "Content-Type": "application/json",
    "Accept": "application/json"
    }

    #Contains payload with address object information
    payload = {
    "entry": [
        {
            "@location": device_group,
            "@name": address_name,
            "ip-netmask" : ip_address,
            "description" : description,
            "tag": {
                "member": tags
                }
            }
        ]
    }
    
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    #POST request with response placed inside a variable 
    response = requests.put(firewall_URL, headers=headers, params=query_params, data=json.dumps(payload), verify=False)

    if response.status_code == 200:
        print("\nAddress Object: " + address_name + " was modified successfully.")
        print("Response:", response.json())
        print('\n')
    else:
        print("Request failed.")
        print("Status Code:", response.status_code)
        print("Response:", response.text)


###


def run_rename_security_policy(ticket_number, decrypted_api):
    """
    Function that pulls data from a CSV file and runs rename_security_policy()
        
    Parameters:
        ticket_number (string) -- Ticket number for the firewall change. Used to create file path for csv location.

        decrypted_api (string) -- API key used to authenticate API calls. Pulled and decrypted in main()
    """  

    csv_end = '<LAST HALF OF CSV FILE PATH>'
    csv_file = csv_start + csv_end

    with open(csv_file, mode='r') as csvfile:
        reader = csv.DictReader(csvfile)
    
        for row in reader:
            device_group = row['device_group']
            rule_name = row['rule_name']
            new_name = row['new_name']
            
            

            __rename_security_policy(device_group, rule_name, new_name, decrypted_api)
            set_audit_comment(device_group, rule_name, ticket_number, decrypted_api)


def __rename_security_policy(device_group, rule_name, new_name, api_key):
    """
    Function that renames a Security Policy

    Parameters:
        device_group (String) -- Device group location. Security rules are placed in different locations via Panorama (Perimeter, Datacenter, etc.)
        rule_name (String) -- This is the name of the security policy.
        new_name (String) -- New name of the security policy
        api_key (String) -- This is the api_key (API key is pulled and decrypted in Main)
    """
    
    firewall_URL = "<PANORAMA OR FIREWALL URL>"

    #Builds URL with query parameters
    query_params = {
    "location": "device-group",
    "name": rule_name,
    "device-group": device_group,
    "newname" : new_name,
    "input-format": "json",
    "output-format": "json"
    }
    
    #Builds the HTTP headers
    headers = {
    "X-PAN-KEY": api_key,
    "Content-Type": "application/json",
    "Accept": "application/json"
    }
    
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    #POST request with response placed inside a variable 
    response = requests.put(firewall_URL, headers=headers, params=query_params)

    if response.status_code == 200:
        print("\nSecurity Rule: " + rule_name + " was successfully named to " + new_name + ".")
        print("Response:", response.json())
        print('\n')
    else:
        print("Request failed.")
        print("Status Code:", response.status_code)
        print("Response:", response.text)


###


def run_rename_nat_policy(ticket_number, decrypted_api):
    """
    Function that pulls data from a CSV file and runs create_nat_policy()
        
    Parameters:
        ticket_number (string) -- Ticket number for the firewall change. Used to create file path for csv location.

        decrypted_api (string) -- API key used to authenticate API calls. Pulled and decrypted in main()
    """  

    csv_end = '<LAST HALF OF CSV FILE PATH>'
    csv_file = csv_start + csv_end

    with open(csv_file, mode='r') as csvfile:
        reader = csv.DictReader(csvfile)
    
        for row in reader:
            device_group = row['device_group']
            rule_name = row['rule_name']
            new_name = row['new_name']
            
            

            __rename_nat_policy(device_group, rule_name, new_name, decrypted_api)


def __rename_nat_policy(device_group, rule_name, new_name, api_key):
    """
    Function that renames a NAT Policy

    Parameters:
        device_group (String) -- Device group location. Security rules are placed in different locations via Panorama (Perimeter, Datacenter, etc.)
        rule_name (String) -- This is the name of the NAT policy.
        new_name (String) -- New name of the NAT policy
        api_key (String) -- This is the api_key (API key is pulled and decrypted in Main)
    """
    
    firewall_URL = "<PANORAMA OR FIREWALL URL>"

    #Builds URL with query parameters
    query_params = {
    "location": "device-group",
    "name": rule_name,
    "device-group": device_group,
    "newname" : new_name,
    "input-format": "json",
    "output-format": "json"
    }
    
    #Builds the HTTP headers
    headers = {
    "X-PAN-KEY": api_key,
    "Content-Type": "application/json",
    "Accept": "application/json"
    }
    
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    #POST request with response placed inside a variable 
    response = requests.put(firewall_URL, headers=headers, params=query_params)

    if response.status_code == 200:
        print("\nNAT Rule: " + rule_name + " was successfully named to " + new_name + ".")
        print("Response:", response.json())
        print('\n')
    else:
        print("Request failed.")
        print("Status Code:", response.status_code)
        print("Response:", response.text)


###


def run_modify_security_policies(ticket_number, decrypted_api):
    """
    Function that pulls data from a CSV file and runs modify_security_policy()
        
    Parameters:
        ticket_number (string) -- Ticket number for the firewall change. Used to create file path for csv location.

        decrypted_api (string) -- API key used to authenticate API calls. Pulled and decrypted in main()
    """  

    csv_end = '<LAST HALF OF CSV FILE PATH>'
    csv_file = csv_start + csv_end

    with open(csv_file, mode='r') as csvfile:
        reader = csv.DictReader(csvfile)
    
        for row in reader:
            device_group = row['device_group']
            rule_name = row['rule_name']
            rule_type = row['rule_type']
            rule_description = row['rule_description']
            action = row['action']
            source_zone = row['source_zone']
            dest_zone = row['dest_zone']
            group_profile = row['group_profile']
            tags = [tag.strip() for tag in row['tags'].split(',')]
            source_ip = [ip.strip() for ip in row['source_ip'].split(',')]
            dest_ip = [ip.strip() for ip in row['dest_ip'].split(',')]
            apps = [app.strip() for app in row['apps'].split(',')]
            services = [service.strip() for service in row['services'].split(',')]
            source_user = [user.strip() for user in row['source_user'].split(',')]
            status = row['disabled']
            
            __modify_security_policy(device_group, rule_name, rule_type, rule_description, action, source_zone, dest_zone, group_profile, tags, source_ip, dest_ip, apps, services, source_user, status, decrypted_api)
            set_audit_comment(device_group, rule_name, ticket_number, decrypted_api)


def __modify_security_policy(device_group, rule_name, rule_type, rule_description, action, source_zone, destination_zone, group_profile, tags, source_ip, destination_ip, apps, services, source_user, status, api_key):
    """
    Function that modifies all elements of a security policy

    Parameters:
        device_group (String) -- Device group location. Security rules are placed in different locations via Panorama (Perimeter, Datacenter, etc.)
        rule_name (String) -- This is the name of the security policy
        rule_type (String) -- Type of rule. This is typcially 'universal'
        rule_description (String) -- Description of the security rule
        action (String) -- This is the action of the security rule (allow, deny, drop, etc)
        source_zone (String) -- The source zone of the security policy
        destination_zone (String) -- The destination zone of the security policy
        group_profile (String) -- Name of the security profile group assigned to the security policy
        tags (String) -- Tag or list of tags associated with the security rule
        source_ip (String) -- Source IP address
        destination_ip (String) -- Destination IP address
        apps (String) -- Application or list of applications assigned to a security rule (SSL, DNS, etc.)
        services (String) -- Service or list of services assigned to a security rule (TCP 3389, UDP 123. etc.)
        source_user (String) -- The users the security policy applies too. Specifiy a user name or set to 'any' if it applies to any user
        status (String) -- To disable rule set this to 'yes'. To enable the rule set this to 'no'
        api_key (String) -- This is the api_key (API key is pulled and decrypted in Main)
    """

    firewall_URL = "<PANORAMA OR FIREWALL URL>"

    #Buuilds the URL 
    query_params = {
    "location": "device-group",
    "name": rule_name,
    "device-group": device_group,
    "input-format": "json",
    "output-format": "json",
    }
    
    #Builds the http header
    headers = {
    "X-PAN-KEY": api_key,
    "Content-Type": "application/json",
    "Accept": "application/json"
    }
    #Builds the payload
    payload = {
    "entry": [
        {
            "@location": device_group,
            "@name": rule_name,
            "rule-type": rule_type,
            "description": rule_description,
            "action": action,
            "log-setting": "Send to Panorama",
            "log-end": "yes",
            "tag": {
                "member": tags
            },
            "from": {
                "member":[
                    source_zone
                ]
            },
            "source": {
                "member": source_ip
            },
            "source-user": {
                "member": source_user
            },
            "to": {
                "member": [
                    destination_zone
                ]
            },
            "destination": {
                "member": destination_ip
            },
            "application": {
                "member": apps
            },
            "service": {
                "member": services
            },
            "profile-setting": {
                "group": {
                    "member": [group_profile]
                }
            },
            "disabled" : status,
        }
    ]
}
    
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    response = requests.put(firewall_URL, headers=headers, params=query_params, data=json.dumps(payload), verify=False)


    if response.status_code == 200:
        print("\nSecurity Policy: " + rule_name + " was modified successfully!")
        print("Response:", response.json())
        print('\n')
    else:
        print("Request failed.")
        print("Status Code:", response.status_code)
        print("Response:", response.text)


###


def run_delete_security_policy(ticket_number, decrypted_api):
    """
    Function that pulls data from a CSV file and runs delete_security_policy()
        
    Parameters:
        ticket_number (string) -- Ticket number for the firewall change. Used to create file path for csv location.

        decrypted_api (string) -- API key used to authenticate API calls. Pulled and decrypted in main()
    """

    csv_end = '<LAST HALF OF CSV FILE PATH>'
    csv_file = csv_start + csv_end

    with open(csv_file, mode='r') as csvfile:
        reader = csv.DictReader(csvfile)
    
        for row in reader:
            device_group = row['device_group']
            rule_name = row['rule_name']
            
            __delete_security_policy(device_group, rule_name, decrypted_api)


def __delete_security_policy(device_group, rule_name, api_key):
    """
    Function that permanently deletes a security policy

    Parameters:
        device_group (String) -- Device group location. Security rules are placed in different locations via Panorama (Perimeter, Datacenter, etc.)
        rule_name (String) -- This is the name of the NAT policy.
        api_key (String) -- This is the api_key (API key is pulled and decrypted in Main)
    """
    
    firewall_URL = "<PANORAMA OR FIREWALL URL>"

    #Builds URL with query parameters
    query_params = {
    "location": "device-group",
    "name": rule_name,
    "device-group": device_group,
    "input-format": "json",
    "output-format": "json"
    }
    
    #Builds the HTTP headers
    headers = {
    "X-PAN-KEY": api_key,
    "Content-Type": "application/json",
    "Accept": "application/json"
    }
    
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    #POST request with response placed inside a variable 
    response = requests.delete(firewall_URL, headers=headers, params=query_params)

    if response.status_code == 200:
        print("\nSecurity Rule: " + rule_name + " was successfully deleted.")
        print("Response:", response.json())
        print('\n')
    else:
        print("Request failed.")
        print("Status Code:", response.status_code)
        print("Response:", response.text)


###


def run_delete_nat_policy(ticket_number, decrypted_api):
    """
    Function that pulls data from a CSV file and runs delete_nat_policy()
        
    Parameters:
        ticket_number (string) -- Ticket number for the firewall change. Used to create file path for csv location.

        decrypted_api (string) -- API key used to authenticate API calls. Pulled and decrypted in main()
    """  

    csv_end = '<LAST HALF OF CSV FILE PATH>'
    csv_file = csv_start + csv_end

    with open(csv_file, mode='r') as csvfile:
        reader = csv.DictReader(csvfile)
    
        for row in reader:
            device_group = row['device_group']
            rule_name = row['rule_name']
            
            __delete_nat_policy(device_group, rule_name, decrypted_api)


def __delete_nat_policy(device_group, rule_name, api_key):
    """
    Function that permanently deletes a NAT Policy

    Parameters:
        device_group (String) -- Device group location. Security rules are placed in different locations via Panorama (Perimeter, Datacenter, etc.)
        rule_name (String) -- This is the name of the NAT policy.
        api_key (String) -- This is the api_key (API key is pulled and decrypted in Main)
    """
    
    firewall_URL = "<PANORAMA OR FIREWALL URL>"

    #Builds URL with query parameters
    query_params = {
    "location": "device-group",
    "name": rule_name,
    "device-group": device_group,
    "input-format": "json",
    "output-format": "json"
    }
    
    #Builds the HTTP headers
    headers = {
    "X-PAN-KEY": api_key,
    "Content-Type": "application/json",
    "Accept": "application/json"
    }
    
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    #DELETE request with response placed inside a variable 
    response = requests.delete(firewall_URL, headers=headers, params=query_params)

    if response.status_code == 200:
        print("\nNAT Rule: " + rule_name + " was successfully deleted.")
        print("Response:", response.json())
        print('\n')
    else:
        print("Request failed.")
        print("Status Code:", response.status_code)
        print("Response:", response.text)






#XML FUNCTIONS --- RUN functions pull new data and call the function below.
#####################################################################################################################################################################################
#####################################################################################################################################################################################
#####################################################################################################################################################################################

def run_change_security_description(ticket_number, decrypted_api):
    """
    Function that pulls data from a CSV file and runs change_security_rule_description()
        
    Parameters:
        ticket_number (string) -- Ticket number for the firewall change. Used to create file path for csv location.

        decrypted_api (string) -- API key used to authenticate API calls. Pulled and decrypted in main()
    """  

    csv_end = '<LAST HALF OF CSV FILE PATH>'
    csv_file = csv_start + csv_end

    with open(csv_file, mode='r') as csvfile:
        reader = csv.DictReader(csvfile)
    
        for row in reader:
            device_group = row['device_group']
            rule_name = row['rule_name']
            description = row['description']
            
            __change_security_rule_description(device_group, rule_name, description, decrypted_api)
            set_audit_comment(device_group, rule_name, ticket_number, decrypted_api)


def __change_security_rule_description(device_group, rule_name, description, api_key):
    """
    XML Function that changes the description within a security policy rule.

    Parameters:
        device_group (String) -- Device group location. Security rules are placed in different locations via Panorama (Perimeter, Datacenter, etc.)
        rule_name (String) -- This is the name of the security policy
        description (String) -- New security policy description
        api_key (String) -- This is the api_key (API key is pulled and decrypted in Main)
    """
    
    xml_URL = "<PANORAMA OR FIREWALL URL>"
    xpath = "<PANORAMA OR FIREWALL XPATH FOR DESCRIPTION ELEMENT>"
    element = "<description>" + description + "</description>"

    #Builds the HTTP headers
    headers = {
    "X-PAN-KEY": api_key
    }

    #Contains payload with address object information
    params = {
        "type" : "config",
        "action" : "edit",
        "xpath": xpath,
        "element": element
    }
    
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    #POST request with response placed inside a variable 
    response = requests.post(xml_URL, headers=headers, params=params, verify=False)

    if response.status_code == 200:
        print("\nSuccessfully changed description for the security rule: " + rule_name)
        print("Response:", response.text)
        print('\n')
    
    else:
        print("Request Failed with status code:", response.status_code)
        print("Response: ", response.text)


###


def run_change_security_policy_source(ticket_number, decrypted_api):
    """
    Function that pulls data from a CSV file and runs change_security_rule_source()
        
    Parameters:
        ticket_number (string) -- Ticket number for the firewall change. Used to create file path for csv location.

        decrypted_api (string) -- API key used to authenticate API calls. Pulled and decrypted in main()
    """  

    csv_end = '<LAST HALF OF CSV FILE PATH>'
    csv_file = csv_start + csv_end

    member_start = "<member>"
    member_end = "</member>"

    with open(csv_file, mode='r') as csvfile:
        reader = csv.DictReader(csvfile)
    
        for row in reader:
            source_start = "<source>"
            source_end = "</source>"   

            for ip in row['source'].split(','):
                member = member_start + ip.strip() + member_end
                source_start += member
            
            element = source_start + source_end
            device_group = row['device_group']
            rule_name = row['rule_name']

            __change_security_rule_source(element, device_group, rule_name, decrypted_api)
            set_audit_comment(device_group, rule_name, ticket_number, decrypted_api)


def __change_security_rule_source(element, device_group, rule_name, api_key):
    """
    XML Function that changes the source IP for a security rule

    Parameters:
        element (String) -- This is the XML location for the specified config (Constructed in the function - run_change_security_description)
        device_group (String) -- Device group location. Security rules are placed in different locations via Panorama (Perimeter, Datacenter, etc.)
        rule_name (String) -- This is the name of the security policy
        api_key (String) -- This is the api_key (API key is pulled and decrypted in Main)
    """
    
    xml_URL = "<PANORAMA OR FIREWALL URL>"
    xpath = "PANORAMA OR FIREWALL XPATH FOR SOURCE IP ELEMENT"

    #Builds the HTTP headers
    headers = {
    "X-PAN-KEY": api_key
    }

    #Contains payload with address object information
    params = {
        "type" : "config",
        "action" : "edit",
        "xpath": xpath,
        "element": element
    }
    
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    #POST request with response placed inside a variable 
    response = requests.post(xml_URL, headers=headers, params=params, verify=False)

    if response.status_code == 200:
        print("\nSuccessfully changed source ip for the security rule: " + rule_name)
        print("Response:", response.text)
        print('\n')
    
    else:
        print("Request Failed with status code:", response.status_code)
        print("Response: ", response.text)


###


def run_change_security_policy_destination(ticket_number, decrypted_api):
    """
    Function that pulls data from a CSV file and runs change_security_rule_destination()
        
    Parameters:
        ticket_number (string) -- Ticket number for the firewall change. Used to create file path for csv location.

        decrypted_api (string) -- API key used to authenticate API calls. Pulled and decrypted in main()
    """  

    csv_end = '<LAST HALF OF CSV FILE PATH>'
    csv_file = csv_start + csv_end

    member_start = "<member>"
    member_end = "</member>"

    with open(csv_file, mode='r') as csvfile:
        reader = csv.DictReader(csvfile)
    
        for row in reader:
            destination_start = "<destination>"
            destination_end = "</destination>"   

            for ip in row['destination'].split(','):
                member = member_start + ip.strip() + member_end
                destination_start += member
            
            element = destination_start + destination_end
            device_group = row['device_group']
            rule_name = row['rule_name']

            __change_security_rule_destination(element, device_group, rule_name, decrypted_api)
            set_audit_comment(device_group, rule_name, ticket_number, decrypted_api)


def __change_security_rule_destination(element, device_group, rule_name, api_key):
    """
    XML Function that changes destination IP configured into a security rule

    Parameters:
        element (String) -- This is the XML location for the specified config (Constructed in the function - run_change_security_description)
        device_group (String) -- Device group location. Security rules are placed in different locations via Panorama (Perimeter, Datacenter, etc.)
        rule_name (String) -- This is the name of the security policy
        api_key (String) -- This is the api_key (API key is pulled and decrypted in Main)
    """
    
    xml_URL = "<PANORAMA OR FIREWALL URL>"
    xpath = "<PANORAMA OR FIREWALL XPATH FOR DESTINATION IP ELEMENT>"

    #Builds the HTTP headers
    headers = {
    "X-PAN-KEY": api_key
    }

    params = {
        "type" : "config",
        "action" : "edit",
        "xpath": xpath,
        "element": element
    }
    
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    #POST request with response placed inside a variable 
    response = requests.post(xml_URL, headers=headers, params=params, verify=False)

    if response.status_code == 200:
        print("\nSuccessfully changed destination ip for the security rule: " + rule_name)
        print("Response:", response.text)
        print('\n')
    
    else:
        print("Request Failed with status code:", response.status_code)
        print("Response: ", response.text)


###


def run_change_security_policy_service(ticket_number, decrypted_api):
    """
    Function that pulls data from a CSV file and runs change_security_rule_service()
        
    Parameters:
        ticket_number (string) -- Ticket number for the firewall change. Used to create file path for csv location.

        decrypted_api (string) -- API key used to authenticate API calls. Pulled and decrypted in main()
    """  

    csv_end = '<LAST HALF OF CSV FILE PATH>'
    csv_file = csv_start + csv_end

    member_start = "<member>"
    member_end = "</member>"

    with open(csv_file, mode='r') as csvfile:
        reader = csv.DictReader(csvfile)
    
        for row in reader:
            service_start = "<service>"
            service_end = "</service>"   

            for ip in row['service'].split(','):
                member = member_start + ip.strip() + member_end
                service_start += member
            
            element = service_start + service_end
            device_group = row['device_group']
            rule_name = row['rule_name']

            __change_security_rule_service(element, device_group, rule_name, decrypted_api)
            set_audit_comment(device_group, rule_name, ticket_number, decrypted_api)


def __change_security_rule_service(element, device_group, rule_name, api_key):
    """
    XML Function that changes the services configured into a security policy

    Parameters:
        element (String) -- This is the XML location for the specified config (Constructed in the function - run_change_security_application)
        device_group (String) -- Device group location. Security rules are placed in different locations via Panorama (Perimeter, Datacenter, etc.)
        rule_name (String) -- This is the name of the security policy
        api_key (String) -- This is the api_key (API key is pulled and decrypted in Main)
    """
    
    xml_URL = ""<PANORAMA OR FIREWALL URL>""
    xpath = "<PANORAMA OR FIREWALL XPATH FOR SERVICE ELEMENT>"

    #Builds the HTTP headers
    headers = {
    "X-PAN-KEY": api_key
    }

    params = {
        "type" : "config",
        "action" : "edit",
        "xpath": xpath,
        "element": element
    }
    
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    #POST request with response placed inside a variable 
    response = requests.post(xml_URL, headers=headers, params=params, verify=False)

    if response.status_code == 200:
        print("\nSuccessfully changed services for the security rule: " + rule_name)
        print("Response:", response.text)
        print('\n')
    
    else:
        print("Request Failed with status code:", response.status_code)
        print("Response: ", response.text)


###


def run_change_security_policy_application(ticket_number, decrypted_api):
    """
    Function that pulls data from a CSV file and runs change_security_rule_application()
        
    Parameters:
        ticket_number (string) -- Ticket number for the firewall change. Used to create file path for csv location.

        decrypted_api (string) -- API key used to authenticate API calls. Pulled and decrypted in main()
    """  

    csv_end = '<LAST HALF OF CSV FILE PATH>'
    csv_file = csv_start + csv_end

    member_start = "<member>"
    member_end = "</member>"

    with open(csv_file, mode='r') as csvfile:
        reader = csv.DictReader(csvfile)
    
        for row in reader:
            application_start = "<application>"
            application_end = "</application>"   

            for ip in row['application'].split(','):
                member = member_start + ip.strip() + member_end
                application_start += member
            
            element = application_start + application_end
            device_group = row['device_group']
            rule_name = row['rule_name']

            __change_security_rule_application(element, device_group, rule_name, decrypted_api)
            set_audit_comment(device_group, rule_name, ticket_number, decrypted_api)


def __change_security_rule_application(element, device_group, rule_name, api_key):
    """
    XML Function that changes the applications configured into security policy

    Parameters:
        element (String) -- This is the XML location for the specified config (Constructed in the function - run_change_security_application)
        device_group (String) -- Device group location. Security rules are placed in different locations via Panorama (Perimeter, Datacenter, etc.)
        rule_name (String) -- This is the name of the security policy
        api_key (String) -- This is the api_key (API key is pulled and decrypted in Main)
    """
    
    xml_URL = ""<PANORAMA OR FIREWALL URL>""
    xpath = "<PANORAMA OR FIREWALL XPATH FOR APPLICATION ELEMENT>"

    #Builds the HTTP headers
    headers = {
    "X-PAN-KEY": api_key
    }

    params = {
        "type" : "config",
        "action" : "edit",
        "xpath": xpath,
        "element": element
    }
    
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    #POST request with response placed inside a variable 
    response = requests.post(xml_URL, headers=headers, params=params, verify=False)

    if response.status_code == 200:
        print("\nSuccessfully changed applications for the security rule: " + rule_name)
        print("Response:", response.text)
        print('\n')
    
    else:
        print("Request Failed with status code:", response.status_code)
        print("Response: ", response.text)


###


def run_change_security_policy_tag(ticket_number, decrypted_api):
    """
    Function that pulls data from a CSV file and runs change_security_rule_tag()
        
    Parameters:
        ticket_number (string) -- Ticket number for the firewall change. Used to create file path for csv location.

        decrypted_api (string) -- API key used to authenticate API calls. Pulled and decrypted in main()
    """

    csv_end = '<LAST HALF OF CSV FILE PATH>'
    csv_file = csv_start + csv_end

    member_start = "<member>"
    member_end = "</member>"

    with open(csv_file, mode='r') as csvfile:
        reader = csv.DictReader(csvfile)
    
        for row in reader:
            tag_start = "<tag>"
            tag_end = "</tag>"   

            for ip in row['tag'].split(','):
                member = member_start + ip.strip() + member_end
                tag_start += member
            
            element = tag_start + tag_end
            device_group = row['device_group']
            rule_name = row['rule_name']

            __change_security_rule_tag(element, device_group, rule_name, decrypted_api)
            set_audit_comment(device_group, rule_name, ticket_number, decrypted_api)


def __change_security_rule_tag(element, device_group, rule_name, api_key):
    """
    XML Function that changes the tags configured into a security policy

    Parameters:
        element (String) -- This is the XML location for the specified config (Constructed in the function - run_change_security_rule_tag)
        device_group (String) -- Device group location. Security rules are placed in different locations via Panorama (Perimeter, Datacenter, etc.)
        rule_name (String) -- This is the name of the security policy
        api_key (String) -- This is the api_key (API key is pulled and decrypted in Main)
    """
    
    xml_URL = "<PANORAMA OR FIREWALL URL>"
    xpath = "PANORAMA OR FIREWALL XPATH FOR TAG ELEMENT"

    #Builds the HTTP headers
    headers = {
    "X-PAN-KEY": api_key
    }

    params = {
        "type" : "config",
        "action" : "edit",
        "xpath": xpath,
        "element": element
    }
    
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    #POST request with response placed inside a variable 
    response = requests.post(xml_URL, headers=headers, params=params, verify=False)

    if response.status_code == 200:
        print("\nSuccessfully changed tags for the security rule: " + rule_name)
        print("Response:", response.text)
        print('\n')
    
    else:
        print("Request Failed with status code:", response.status_code)
        print("Response: ", response.text)


###


def run_disable_security_policy(ticket_number, decrypted_api):
    """
    Function that pulls data from a CSV file and runs disable_security_policy()
        
    Parameters:
        ticket_number (string) -- Ticket number for the firewall change. Used to create file path for csv location.

        decrypted_api (string) -- API key used to authenticate API calls. Pulled and decrypted in main()
    """  

    csv_end = '<LAST HALF OF CSV FILE PATH>'
    csv_file = csv_start + csv_end

    with open(csv_file, mode='r') as csvfile:
        reader = csv.DictReader(csvfile)
    
        for row in reader:
            device_group = row['device_group']
            rule_name = row['rule_name']

            __disable_security_policy(device_group, rule_name, decrypted_api)
            set_audit_comment(device_group, rule_name, ticket_number, decrypted_api)


def __disable_security_policy(device_group, rule_name, api_key):
    """
    XML Function that disables a security policy

    Parameters:
        device_group (String) -- Device group location. Security rules are placed in different locations via Panorama (Perimeter, Datacenter, etc.)
        rule_name (String) -- This is the name of the security policy
        api_key (String) -- This is the api_key (API key is pulled and decrypted in Main)
    """
    
    xml_URL = "<PANORAMA OR FIREWALL URL>"
    xpath = "PANORAMA OR FIREWALL XPATH FOR DISABLE ELEMENT"
    element = "<disabled>yes</disabled>"
    
    #Builds the HTTP headers
    headers = {
    "X-PAN-KEY": api_key
    }

    params = {
        "type" : "config",
        "action" : "set",
        "xpath": xpath,
        "element": element
    }
    
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    #POST request with response placed inside a variable 
    response = requests.post(xml_URL, headers=headers, params=params, verify=False)

    if response.status_code == 200:
        print("\nSuccessfully disabled security rule: " + rule_name)
        print("Response:", response.text)
        print('\n')
    
    else:
        print("Request Failed with status code:", response.status_code)
        print("Response: ", response.text)


###


def run_disable_nat_policy(ticket_number, decrypted_api):
    """
    Function that pulls data from a CSV file and runs disable_nat_policy()
        
    Parameters:
        ticket_number (string) -- Ticket number for the firewall change. Used to create file path for csv location.

        decrypted_api (string) -- API key used to authenticate API calls. Pulled and decrypted in main()
    """  

    csv_end = '<LAST HALF OF CSV FILE PATH>'
    csv_file = csv_start + csv_end

    with open(csv_file, mode='r') as csvfile:
        reader = csv.DictReader(csvfile)
    
        for row in reader:
            device_group = row['device_group']
            rule_name = row['rule_name']

            __disable_nat_policy(device_group, rule_name, decrypted_api)
            set_audit_comment(device_group, rule_name, ticket_number, decrypted_api)


def __disable_nat_policy(device_group, rule_name, api_key):
    """
    XML Function that disables a NAT Policy

    Parameters: 
        device_group (String) -- Device group location. Security rules are placed in different locations via Panorama (Perimeter, Datacenter, etc.)
        rule_name (String) -- This is the NAT Policy name
        api_key (String) -- This is the api_key (API key is pulled and decrypted in Main)
    """
    
    xml_URL = "<PANORAMA OR FIREWALL URL>"
    xpath = "PANORAMA OR FIREWALL XPATH FOR DISABLE ELEMENT"
    element = "<disabled>yes</disabled>"
    
    #Builds the HTTP headers
    headers = {
    "X-PAN-KEY": api_key
    }

    params = {
        "type" : "config",
        "action" : "set",
        "xpath": xpath,
        "element": element
    }
    
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    #POST request with response placed inside a variable 
    response = requests.post(xml_URL, headers=headers, params=params, verify=False)

    if response.status_code == 200:
        print("\nSuccessfully disabled nat rule: " + rule_name)
        print("Response:", response.text)
        print('\n')
    
    else:
        print("Request Failed with status code:", response.status_code)
        print("Response: ", response.text)


###


def run_change_address_tag(ticket_number, decrypted_api):
    """
    Function that pulls data from a CSV file and runs change_address_tag()
        
    Parameters:
        ticket_number (string) -- Ticket number for the firewall change. Used to create file path for csv location.

        decrypted_api (string) -- API key used to authenticate API calls. Pulled and decrypted in main()
    """  

    csv_end = '<LAST HALF OF CSV FILE PATH>'
    csv_file = csv_start + csv_end

    member_start = "<member>"
    member_end = "</member>"

    with open(csv_file, mode='r') as csvfile:
        reader = csv.DictReader(csvfile)
    
        for row in reader:
            tag_start = "<tag>"
            tag_end = "</tag>"   

            for ip in row['tag'].split(','):
                member = member_start + ip.strip() + member_end
                tag_start += member
            
            element = tag_start + tag_end
            address_name = row['address_name']

            __change_address_tag(element, address_name, decrypted_api)


def __change_address_tag(element, address_name, api_key):
    """
    XML Function that modifies the tag configured to an address object

    Parameters:
        element (String) -- This is the XML location for the specified config (Constructed in the function - run_change_address_tag)
        address_name (String) -- This is the name of the address object.
        api_key (String) -- This is the api_key (API key is pulled and decrypted in Main)
    """
    
    xml_URL = "<PANORAMA OR FIREWALL URL>"
    xpath = "PANORAMA OR FIREWALL XPATH FOR TAG ELEMENT"

    #Builds the HTTP headers
    headers = {
    "X-PAN-KEY": api_key
    }

    params = {
        "type" : "config",
        "action" : "edit",
        "xpath": xpath,
        "element": element
    }
    
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    #POST request with response placed inside a variable 
    response = requests.post(xml_URL, headers=headers, params=params, verify=False)

    if response.status_code == 200:
        print("\nSuccessfully changed tags for the address object: " + address_name)
        print("Response:", response.text)
        print('\n')
    
    else:
        print("Request Failed with status code:", response.status_code)
        print("Response: ", response.text)


###


def run_change_address_group_tag(ticket_number, decrypted_api):
    """
    Function that pulls data from a CSV file and runs change_address_gorup_tag()
        
    Parameters:
        ticket_number (string) -- Ticket number for the firewall change. Used to create file path for csv location.

        decrypted_api (string) -- API key used to authenticate API calls. Pulled and decrypted in main()
    """ 

    csv_end = '<LAST HALF OF CSV FILE PATH>'
    csv_file = csv_start + csv_end

    member_start = "<member>"
    member_end = "</member>"

    with open(csv_file, mode='r') as csvfile:
        reader = csv.DictReader(csvfile)
    
        for row in reader:
            tag_start = "<tag>"
            tag_end = "</tag>"   

            for ip in row['tag'].split(','):
                member = member_start + ip.strip() + member_end
                tag_start += member
            
            element = tag_start + tag_end
            group_name = row['address_group']

            __change_address_group_tag(element, group_name, decrypted_api)


def __change_address_group_tag(element, group_name, api_key):
    """
    XML Function that changes the tags within an address group
    
    Parameters:
        element (String) -- This is the XML location for the specified config (Constructed in the function - run_change_address_group_tag)
        group_name (String) -- This is the address group name
        api_key (String) -- This is the api_key (API key is pulled and decrypted in Main)
    """
    
    xml_URL = "<PANORAMA OR FIREWALL URL>"
    xpath = "PANORAMA OR FIREWALL XPATH FOR TAG ELEMENT"

    #Builds the HTTP headers
    headers = {
    "X-PAN-KEY": api_key
    }

    params = {
        "type" : "config",
        "action" : "edit",
        "xpath": xpath,
        "element": element
    }
    
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    #POST request with response placed inside a variable 
    response = requests.post(xml_URL, headers=headers, params=params, verify=False)

    if response.status_code == 200:
        print("\nSuccessfully changed tags for the address group: " + group_name)
        print("Response:", response.text)
        print('\n')
    
    else:
        print("Request Failed with status code:", response.status_code)
        print("Response: ", response.text)


###


def run_change_security_log_setting(ticket_number, decrypted_api):
    """
    Function that pulls data from a CSV file and runs change_security_log_setting()
        
    Parameters:
        ticket_number (string) -- Ticket number for the firewall change. Used to create file path for csv location.

        decrypted_api (string) -- API key used to authenticate API calls. Pulled and decrypted in main()
    """  

    csv_end = '<LAST HALF OF CSV FILE PATH>'
    csv_file = csv_start + csv_end

    log_setting_start = "<log-setting>"
    log_setting_end = "</log-setting>"

    with open(csv_file, mode='r') as csvfile:
        reader = csv.DictReader(csvfile)
    
        for row in reader:
            
            device_group = row['device_group']
            rule_name = row['rule_name']
            log_setting = row['log_setting']
            element = log_setting_start + log_setting + log_setting_end
            
            __change_security_log_setting(element, device_group, rule_name, decrypted_api)
            set_audit_comment(device_group, rule_name, ticket_number, decrypted_api)


def __change_security_log_setting(element, device_group, rule_name, api_key):
    """
    XML Function that changes the log forwarding profile setting within a security rule.

    Parameters: 
        element (String) -- This is the XML location for the specified config (Constructed in the function - run_change_security_log_setting)
        device_group (String) -- Device group location. Security rules are placed in different locations via Panorama (Perimeter, Datacenter, etc.)
        rule_name (String) -- Security rule name
        api_key (String) -- This is the api_key (API key is pulled and decrypted in Main)
    """
    
    xml_URL = "<PANORAMA OR FIREWALL URL>"
    xpath_start = "<FIRST HALF OF XPATH>"
    device_xpath = "<DEVICE GROUP VARIABLE XPATH>"
    rule_xpath = "LAST HALF OF XPATH"
    #log_xpath = "log-setting/member[@name='" + log_setting + "']"

    full_xpath = xpath_start + device_xpath + rule_xpath

    #Builds the HTTP headers
    headers = {
    "X-PAN-KEY": api_key
    }

    params = {
        "type" : "config",
        "action" : "edit",
        "xpath": full_xpath,
        "element": element
    }
    
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    #POST request with response placed inside a variable
    response = requests.post(xml_URL, headers=headers, params=params, verify=False)

    if response.status_code == 200:
        print("\nSuccessfully changed log setting for rule: " + rule_name)
        print("Response:", response.text)
        print('\n')
    
    else:
        print("Request Failed with status code:", response.status_code)
        print("Response: ", response.text)


###


def set_audit_comment(device_group, rule_name, audit_comment, api_key):
    """
    XML Function that adds the required Audit Comment when security rules are canged.

    Parameters:
        device_group (String) -- Device group location. Security rules are placed in different locations via Panorama (Perimeter, Datacenter, etc.)
        rule_name (String) -- Security rule name
        audit_comment (String) -- This is the audit comment, which is the ticket number parameter from parent function.
        api_key (String) -- This is the api_key (API key is pulled and decrypted in Main)
    """
    
    xml_URL = "<PANORAMA OR FIREWALL URL>"
    xpath = "PANORAMA OR FIREWALL XPATH FOR AUDIT COMMENT"
    cmd = "<set><audit-comment><xpath>" + xpath + "</xpath><comment>" + audit_comment + "</comment></audit-comment></set>"

    #Builds the HTTP headers
    headers = {
    "X-PAN-KEY": api_key
    }

    #Contains payload with address object information
    params = {
        "type" : "op",
        "cmd" : cmd
    }
    
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    #POST request with response placed inside a variable 
    response = requests.post(xml_URL, headers=headers, params=params, verify=False)

    if response.status_code == 200:
        print("\nAudit comment added to security rule: " + rule_name)
        print("Response:", response.text)
        print('\n')
    
    else:
        print("Request Failed with status code:", response.status_code)
        print("Response: ", response.text)





#Commit and Push scripts
#####################################################################################################################################################################################
#####################################################################################################################################################################################
#####################################################################################################################################################################################
def create_MDR_blocked_address(api_key):
    """Sample Function used to add address to MDR Blocked IP list. THIS FUNCTION IS FOR EXAMPLE PURPOSES ONLY.

        Parameters:
        -- api_key (string): API key used for authenticating Palo Alto API calls

    """
    
    firewall_URL = "<PANORAMA OR FIREWALL URL>" #Required 
    device_group = "<DEVICE GROUP NAME>" #Required
    tag = '<TAG NAME>' #Required
    object_IP = 'OBJECT IP ADDRESS' #Sample IP Address
    object_description = 'Ex. Malicious IP blocked by MDR after hours' #Sample description

    #Required - Builds URL with query parameters
    parameters = {
    "location": "device-group",
    "name": object_IP, #IP address
    "device-group": device_group,
    "input-format": "json",
    "output-format": "json"
    }
    
    #Required - Builds the HTTP headers
    headers = {
    "X-PAN-KEY": api_key,
    "Content-Type": "application/json",
    "Accept": "application/json"
    }

    #Required - Contains data for address object creation
    data = {
    "entry": [
        {
            "@location": device_group,
            "@name": object_IP,
            "description": object_description,
            "ip-netmask": object_IP,
            "tag": {
                "member": tag
                }
            }
        ]
    }
    
    #Optional - Disables warnings
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    #Required - POST request with response placed inside variable 
    response = requests.post(firewall_URL, headers=headers, params=parameters, data=json.dumps(data), verify=False)

    #Optional
    if response.status_code == 200:
        print("\nAddress object: " + object_IP + " was created successfully.")
        print("Response:", response.json())
        print('\n')
    else:
        print("Request failed.")
        print("Status Code:", response.status_code)
        print("Response:", response.text)



def commit_to_panorama(api_key):
    """Commit -- Pushes the configs to Panorama
        
        Parameters:
        -- api_key (string): API key used for authenticating Palo Alto API calls
    
    """

    xml_URL = "<PANORAMA OR FIREWALL URL>"

    headers = {
    "X-PAN-KEY": api_key
    }

    params = {
        "type" : "commit",
        "cmd" : "<commit></commit>"
    }
    
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    #POST request with response placed inside a variable 
    response = requests.post(xml_URL, headers=headers, params=params, verify=False)

    if response.status_code == 200:
        print("\nSuccessfully committed changes")
        print("Response:", response.text)
        print('\n')
    
    else:
        print("Request Failed with status code:", response.status_code)
        print("Response: ", response.text)



def push_to_perimeter(api_key):
    """Commit-all -- Pushes configs to the Perimeter Firewalls
    
        Parameters:
        -- api_key (string): API key used for authenticating Palo Alto API calls

    """

    xml_URL = "<PANORAMA OR FIREWALL URL>"

    headers = {
    "X-PAN-KEY": api_key
    }

    params = {
        "type" : "commit",
        "action" : "all",
        "cmd" : "<commit-all><shared-policy><device-group><entry name='<DEVICE GROUP NAME>'></entry></device-group></shared-policy></commit-all>"
    }
    
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    #POST request with response placed inside a variable 
    response = requests.post(xml_URL, headers=headers, params=params, verify=False)

    if response.status_code == 200:
        print("\nSuccessfully committed changes")
        print("Response:", response.text)
        print('\n')
    
    else:
        print("Request Failed with status code:", response.status_code)
        print("Response: ", response.text)



def push_to_datacenter(api_key):
    """Commit-all -- Pushes configs to the Datacenter Firewalls
    
        Parameters:
        -- api_key (string): API key used for authenticating Palo Alto API calls
    
    """

    xml_URL = "<PANORAMA OR FIREWALL URL>"

    headers = {
    "X-PAN-KEY": api_key
    }

    params = {
        "type" : "commit",
        "action" : "all",
        "cmd" : "<commit-all><shared-policy><device-group><entry name='<DEVICE GROUP NAME>'></entry></device-group></shared-policy></commit-all>"
    }
    
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    #POST request with response placed inside a variable 
    response = requests.post(xml_URL, headers=headers, params=params, verify=False)

    if response.status_code == 200:
        print("\nSuccessfully committed changes")
        print("Response:", response.text)
        print('\n')
    
    else:
        print("Request Failed with status code:", response.status_code)
        print("Response: ", response.text)







#TESTING
#####################################################################################################################################################################################
#####################################################################################################################################################################################
#####################################################################################################################################################################################


def show_completed_tasks(api_key):
    """ WORKS BUT I NEED NEED TO FIGURE OUT THE FORMATTING """
    
    xml_URL = "<PANORAMA OR FIREWALL URL>"


    #Builds the HTTP headers
    headers = {
    "X-PAN-KEY": api_key
    }

    #Contains payload with address object information
    params = {
        "type" : "op",
        "cmd" : "<show><jobs><processed></processed></jobs></show>"
    }
    
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    #POST request with response placed inside a variable 
    response = requests.get(xml_URL, headers=headers, params=params, verify=False)

    if response.status_code == 200:
        print("\nCompleted Tasks: ")
        print("Response:", response.text)
        print('\n')
    
    else:
        print("Request Failed with status code:", response.status_code)
        print("Response: ", response.text)



def reset_hit_count(device_group, rule_name, api_key):
    """NEED TO FIGURE OUT HOW TO APPLY THIS TO A SPECIFIC RULE"""
    
    xml_URL = "<PANORAMA OR FIREWALL URL>"


    #Builds the HTTP headers
    headers = {
    "X-PAN-KEY": api_key
    }

    #Contains payload with address object information
    params = {
        "type" : "op",
        "cmd" : "<clear><rule-hit-count><device-group><entry name='" + device_group + "'></entry></device-group></rule-hit-count></clear>"
    }
    
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    #POST request with response placed inside a variable 
    response = requests.get(xml_URL, headers=headers, params=params, verify=False)

    if response.status_code == 200:
        print("\nAudit comment added to security rule: " + rule_name)
        print("Response:", response.text)
        print('\n')
    
    else:
        print("Request Failed with status code:", response.status_code)
        print("Response: ", response.text)



def show_security_hit_count(device_group, rule_name, api_key):
    """NEED TO FIGURE OUT HOW TO PROPERLY CALL THIS FUNCTION"""
    
    xml_URL = "<PANORAMA OR FIREWALL URL>"
    xpath = "<PANORAMA OR FIREWALL XPATH>"
    element = "<show><rule-hit-count><device-group></device-group></rule-hit-count></show>"

    #Builds the HTTP headers
    headers = {
    "X-PAN-KEY": api_key
    }

    #Contains payload with address object information
    params = {
        "type" : "op",
        "cmd" : element
    }
    
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    #POST request with response placed inside a variable 
    response = requests.get(xml_URL, headers=headers, params=params, verify=False)

    if response.status_code == 200:
        print("\nHit count for rule: " + rule_name)
        print("Response:", response.text)
        print('\n')
    
    else:
        print("Request Failed with status code:", response.status_code)
        print("Response: ", response.text)





