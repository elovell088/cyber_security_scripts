#This contains Palo Alto API Functions -- Written by: Eric Lovell


#Imports
import sys
import requests
import json
import csv
import urllib3


#File Start
csv_start = '<CSV START FILE PATH FOR DATA GOES HERE>'


#REST Run Functions
#####################################################################################################################################################################################
#####################################################################################################################################################################################
#####################################################################################################################################################################################
def run_address_objects(ticket_number, decrypted_api):
    """This function pulls data from a CSV file and runs the create address group function
    """

    csv_end = '<CSV FILE PATH>'
    csv_file = csv_start + ticket_number + csv_end

    with open(csv_file, mode='r') as csvfile: 
        reader = csv.DictReader(csvfile)
    
        for row in reader:
            ip_address = row['ip_address']
            description = row['description']
            tags = [tag.strip() for tag in row['tags'].split(',')]
            
            create_address_object(ip_address, description, tags, decrypted_api)



def run_address_groups(ticket_number, decrypted_api):

    csv_end = '<CSV FILE PATH>'
    csv_file = csv_start + ticket_number + csv_end

    with open(csv_file, mode='r') as csvfile: 
        reader = csv.DictReader(csvfile)
    
        for row in reader:
            group_name = row['group_name']
            description = row['description']
            addresses = [address.strip() for address in row['addresses'].split(',')]
            tags = [tag.strip() for tag in row['tags'].split(',')]
            
            create_address_groups(group_name, description, addresses, tags, decrypted_api)



def run_service_objects(ticket_number, decrypted_api):

    csv_end = '<CSV FILE PATH>'
    csv_file = csv_start + ticket_number + csv_end

    with open(csv_file, mode='r') as csvfile:
        reader = csv.DictReader(csvfile)
    
        for row in reader:
            service_name = row['service_name']
            protocol = row['protocol']
            port = row['port']
            
            create_service_object(service_name, protocol, port, decrypted_api)



def run_service_groups(ticket_number, decrypted_api):
    
    csv_end = '<CSV FILE PATH>'
    csv_file = csv_start + ticket_number + csv_end

    with open(csv_file, mode='r') as csvfile:
        reader = csv.DictReader(csvfile)
    
        for row in reader:
            group_name = row['group_name']
            services = [service.strip() for service in row['services'].split(',')]
            tags = [tag.strip() for tag in row['tags'].split(',')]
            
            create_service_group(group_name, services, tags, decrypted_api)



def run_application_object(ticket_number, decrypted_api):
    
    csv_end = '<CSV FILE PATH>'
    csv_file = csv_start + ticket_number + csv_end

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

                create_application_object(app_name, description, category, subcategory, technology, risk, port, sig_name, sig_comment, and_name, or_name, operator, pattern_context, pattern, decrypted_api)



def run_application_groups(ticket_number, decrypted_api):
    
    csv_end = '<CSV FILE PATH>
    csv_file = csv_start + ticket_number + csv_end

    with open(csv_file, mode='r') as csvfile:
        reader = csv.DictReader(csvfile)
    
        for row in reader:
            group_name = row['group_name']
            services = [service.strip() for service in row['applications'].split(',')]
            
            create_application_group(group_name, services, decrypted_api)



def run_security_policies(ticket_number, decrypted_api):
    
    csv_end = '<CSV FILE PATH>'
    csv_file = csv_start + ticket_number + csv_end

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
            
            create_security_policy(decrypted_api, device_group, rule_name, rule_type, rule_description, action, source_zone, dest_zone, group_profile, tags, source_ip, dest_ip, apps, services, source_user)
            set_audit_comment(device_group, rule_name, ticket_number, decrypted_api)



def run_move_security_policies(ticket_number, decrypted_api):
    
    move_end = '<CSV FILE PATH>'
    move_file = csv_start + ticket_number + move_end

    with open(move_file, mode='r') as csvfile:
        reader = csv.DictReader(csvfile)
    
        for row in reader:
            rule_name = row['rule_name']
            device_group = row['device_group']
            target = row['target']

            move_security_policy(decrypted_api, rule_name, device_group, target)



def run_nat_policies(ticket_number, decrypted_api):
    
    csv_end = '<CSV FILE PATH>'
    csv_file = csv_start + ticket_number + csv_end
    device_group = 'Perimeter'

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
            
            
            create_nat_policy(rule_name, description, tags, source_zone, destination_zone, source_ip, destination_ip, services, public_ip, direction, decrypted_api)



def run_move_nat_policies(ticket_number, decrypted_api):
    
    move_end = '<CSV FILE PATH>'
    move_file = csv_start + ticket_number + move_end

    with open(move_file, mode='r') as csvfile:
        reader = csv.DictReader(csvfile)
    
        for row in reader:
            rule_name = row['rule_name']
            device_group = row['device_group']
            target = row['target']

            move_nat_policy(decrypted_api, rule_name, device_group, target)



def run_modify_nat(ticket_number, decrypted_api):
    
    csv_end = '<CSV FILE PATH>'
    csv_file = csv_start + ticket_number + csv_end

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
            

            modify_nat_rule(rule_name, source_zone, destination_zone, source_ip, destination_ip, service, tags, status, public_ip, direction, decrypted_api)



def run_modify_address(ticket_number, decrypted_api):
    
    csv_end = '<CSV FILE PATH>'
    csv_file = csv_start + ticket_number + csv_end

    with open(csv_file, mode='r') as csvfile:
        reader = csv.DictReader(csvfile)
    
        for row in reader:
            address_name = row['address_name']
            ip_address = row['ip_address']
            description = row['description']
            tags = [tag.strip() for tag in row['tags'].split(',')]
            

            modify_address_object(address_name, ip_address, description, tags, decrypted_api)



def run_rename_security_policy(ticket_number, decrypted_api):
    
    csv_end = '<CSV FILE PATH>'
    csv_file = csv_start + ticket_number + csv_end

    with open(csv_file, mode='r') as csvfile:
        reader = csv.DictReader(csvfile)
    
        for row in reader:
            device_group = row['device_group']
            rule_name = row['rule_name']
            new_name = row['new_name']
            
            

            rename_security_policy(device_group, rule_name, new_name, decrypted_api)
            set_audit_comment(device_group, rule_name, ticket_number, decrypted_api)



def run_rename_nat_policy(ticket_number, decrypted_api):
    
    csv_end = '<CSV FILE PATH>'
    csv_file = csv_start + ticket_number + csv_end

    with open(csv_file, mode='r') as csvfile:
        reader = csv.DictReader(csvfile)
    
        for row in reader:
            device_group = row['device_group']
            rule_name = row['rule_name']
            new_name = row['new_name']
            
            

            rename_nat_policy(device_group, rule_name, new_name, decrypted_api)



def run_modify_security_policies(ticket_number, decrypted_api):
    
    csv_end = '<CSV FILE PATH>'
    csv_file = csv_start + ticket_number + csv_end

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
            
            modify_security_policy(device_group, rule_name, rule_type, rule_description, action, source_zone, dest_zone, group_profile, tags, source_ip, dest_ip, apps, services, source_user, status, decrypted_api)
            set_audit_comment(device_group, rule_name, ticket_number, decrypted_api)



def run_delete_security_policy(ticket_number, decrypted_api):
    
    csv_end = '<CSV FILE PATH>'
    csv_file = csv_start + ticket_number + csv_end

    with open(csv_file, mode='r') as csvfile:
        reader = csv.DictReader(csvfile)
    
        for row in reader:
            device_group = row['device_group']
            rule_name = row['rule_name']
            
            delete_security_policy(device_group, rule_name, decrypted_api)



def run_delete_nat_policy(ticket_number, decrypted_api):
    
    csv_end = '<CSV FILE PATH>'
    csv_file = csv_start + ticket_number + csv_end

    with open(csv_file, mode='r') as csvfile:
        reader = csv.DictReader(csvfile)
    
        for row in reader:
            device_group = row['device_group']
            rule_name = row['rule_name']
            
            delete_nat_policy(device_group, rule_name, decrypted_api)




#XML Run Functions
#####################################################################################################################################################################################
#####################################################################################################################################################################################
#####################################################################################################################################################################################

def run_change_security_description(ticket_number, decrypted_api):
    
    csv_end = '<CSV FILE PATH>'
    csv_file = csv_start + ticket_number + csv_end

    with open(csv_file, mode='r') as csvfile:
        reader = csv.DictReader(csvfile)
    
        for row in reader:
            device_group = row['device_group']
            rule_name = row['rule_name']
            description = row['description']
            
            change_security_rule_description(device_group, rule_name, description, decrypted_api)
            #set_audit_comment(device_group, rule_name, ticket_number, decrypted_api)



def run_change_security_policy_source(ticket_number, decrypted_api):
    
    csv_end = '<CSV FILE PATH>'
    csv_file = csv_start + ticket_number + csv_end

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

            change_security_rule_source(element, device_group, rule_name, decrypted_api)
            set_audit_comment(device_group, rule_name, ticket_number, decrypted_api)



def run_change_security_policy_destination(ticket_number, decrypted_api):
    
    csv_end = '<CSV FILE PATH>'
    csv_file = csv_start + ticket_number + csv_end

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

            change_security_rule_destination(element, device_group, rule_name, decrypted_api)
            set_audit_comment(device_group, rule_name, ticket_number, decrypted_api)



def run_change_security_policy_service(ticket_number, decrypted_api):
    
    csv_end = '<CSV FILE PATH>'
    csv_file = csv_start + ticket_number + csv_end

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

            change_security_rule_service(element, device_group, rule_name, decrypted_api)
            set_audit_comment(device_group, rule_name, ticket_number, decrypted_api)



def run_change_security_policy_application(ticket_number, decrypted_api):
    
    csv_end = '<CSV FILE PATH>'
    csv_file = csv_start + ticket_number + csv_end

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

            change_security_rule_application(element, device_group, rule_name, decrypted_api)
            set_audit_comment(device_group, rule_name, ticket_number, decrypted_api)



def run_change_security_policy_tag(ticket_number, decrypted_api):
    
    csv_end = '<CSV FILE PATH>'
    csv_file = csv_start + ticket_number + csv_end

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

            change_security_rule_tag(element, device_group, rule_name, decrypted_api)
            set_audit_comment(device_group, rule_name, ticket_number, decrypted_api)



def run_disable_security_policy(ticket_number, decrypted_api):
    
    csv_end = '<CSV FILE PATH>'
    csv_file = csv_start + ticket_number + csv_end

    with open(csv_file, mode='r') as csvfile:
        reader = csv.DictReader(csvfile)
    
        for row in reader:
            device_group = row['device_group']
            rule_name = row['rule_name']

            disable_security_policy(device_group, rule_name, decrypted_api)
            set_audit_comment(device_group, rule_name, ticket_number, decrypted_api)



def run_disable_nat_policy(ticket_number, decrypted_api):
    
    csv_end = '<CSV FILE PATH>'
    csv_file = csv_start + ticket_number + csv_end

    with open(csv_file, mode='r') as csvfile:
        reader = csv.DictReader(csvfile)
    
        for row in reader:
            device_group = row['device_group']
            rule_name = row['rule_name']

            disable_nat_policy(device_group, rule_name, decrypted_api)
            set_audit_comment(device_group, rule_name, ticket_number, decrypted_api)



def run_change_address_tag(ticket_number, decrypted_api):
    
    csv_end = '<CSV FILE PATH>'
    csv_file = csv_start + ticket_number + csv_end

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

            change_address_tag(element, address_name, decrypted_api)



def run_change_address_group_tag(ticket_number, decrypted_api):
    
    csv_end = '<CSV FILE PATH>'
    csv_file = csv_start + ticket_number + csv_end

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

            change_address_group_tag(element, group_name, decrypted_api)



def run_change_security_log_setting(ticket_number, decrypted_api):
    
    csv_end = '<CSV FILE PATH>'
    csv_file = csv_start + ticket_number + csv_end

    log_setting_start = "<log-setting>"
    log_setting_end = "</log-setting>"

    with open(csv_file, mode='r') as csvfile:
        reader = csv.DictReader(csvfile)
    
        for row in reader:
            
            device_group = row['device_group']
            rule_name = row['rule_name']
            log_setting = row['log_setting']
            element = log_setting_start + log_setting + log_setting_end
            
            change_security_log_setting(element, device_group, rule_name, decrypted_api)
            #set_audit_comment(device_group, rule_name, ticket_number, decrypted_api)




#REST Functions -- CREATE
#####################################################################################################################################################################################
#####################################################################################################################################################################################
#####################################################################################################################################################################################
def create_address_object(object_IP, object_description, tag_name, api_key):
    """Function that creates an address object"""
    
    firewall_URL = "<PANORAMA/FIREWALL URL>"
    device_group = "<DEVICE GROUP"

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



def create_address_groups(group_name, group_description, address, tag_name, api_key):
    """Function that creates an address object"""
    
    firewall_URL = "<PANORAMA/FIREWALL URL>"
    device_group = "<DEVICE GROUP"

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



def create_application_object(app_name,description,category,subcategory,technology,risk,port,sig_name,sig_comment,and_name,or_name,operator,pattern_context,pattern,api_key):
    """Function that creates an application object"""
    
    firewall_URL = "<PANORAMA/FIREWALL URL>"
    device_group = "<DEVICE GROUP"

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



def create_application_group(group_name, applications, api_key):
    """Function that creates an application group"""
    
    firewall_URL = "<PANORAMA/FIREWALL URL>"
    device_group = "<DEVICE GROUP"

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



def create_security_policy(api_key,device_group,rule_name,rule_type,rule_description,action,source_zone,dest_zone,group_profile,tags,source_ip,dest_ip,apps,services,source_user):

    firewall_URL = "<PANORAMA/FIREWALL URL>"

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



def move_security_policy(api_key, rule_name, device_group, target):
    """Function that moves a security policy"""
    
    move_URL = "<PANORAMA/FIREWALL URL>"

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



def move_nat_policy(api_key, rule_name, device_group, target):
    """Function that moves a security policy"""
    
    move_URL = "<PANORAMA/FIREWALL URL>"

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



def create_service_object(service_name, protocol, port, api_key):
    """Function that creates an address object"""
    
    firewall_URL = "<PANORAMA/FIREWALL URL>"
    device_group = "<DEVICE GROUP"

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



def create_service_group(group_name, services, tag_name, api_key):
    """Function that creates an address object"""
    
    firewall_URL = "<PANORAMA/FIREWALL URL>"
    device_group = "<DEVICE GROUP"

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
  


def create_nat_policy(rule_name, description, tags, source_zone, destination_zone, source_ip, destination_ip, services, public_ip, direction, api_key):
    
    firewall_URL = "<PANORAMA/FIREWALL URL>"
    device_group = "<DEVICE GROUP"

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




#REST Functions -- MODIFY
#####################################################################################################################################################################################
#####################################################################################################################################################################################
#####################################################################################################################################################################################
def modify_nat_rule(rule_name, source_zone, destination_zone, source_ip, destination_ip, service, tags, status, public_ip, direction, api_key):
    """Function that modifies NAT rules"""
    
    firewall_URL = "<PANORAMA/FIREWALL URL>"
    device_group = "<DEVICE GROUP"

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



def modify_security_policy(device_group, rule_name, rule_type, rule_description, action, source_zone, destination_zone, group_profile, tags, source_ip, destination_ip, apps, services, source_user, status, api_key):
    
    firewall_URL = "<PANORAMA/FIREWALL URL>"

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



def modify_address_object(address_name, ip_address, description, tags, api_key):
    """Function that modifies NAT rules"""
    
    firewall_URL = "<PANORAMA/FIREWALL URL>"
    device_group = "<DEVICE GROUP"

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



def rename_security_policy(device_group, rule_name, new_name, api_key):

    """Function that renames a securtiy policy"""
    
    firewall_URL = "<PANORAMA/FIREWALL URL>"

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



def rename_nat_policy(device_group, rule_name, new_name, api_key):

    """Function that renames a securtiy policy"""
    
    firewall_URL = "<PANORAMA/FIREWALL URL>"

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



def delete_security_policy(device_group, rule_name, api_key):
    """Function that renames a securtiy policy"""
    
    firewall_URL = "<PANORAMA/FIREWALL URL>"

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



def delete_nat_policy(device_group, rule_name, api_key):
    """Function that renames a securtiy policy"""
    
    firewall_URL = "<PANORAMA/FIREWALL URL>"

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





#XML Functions
#####################################################################################################################################################################################
#####################################################################################################################################################################################
#####################################################################################################################################################################################
def change_security_rule_description(device_group, rule_name, description, api_key):
    """"""
    
    xml_URL = "<PANORAMA/FIREWALL URL>"
   
    xpath = "<XPATH GOES HERE>"
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



def change_security_rule_source(element, device_group, rule_name, api_key):
    """Modifies the source IP's within a security rule"""
    
    xml_URL = "<PANORAMA/FIREWALL URL>"
    xpath = "<XPATH GOES HERE>"

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



def change_security_rule_destination(element, device_group, rule_name, api_key):
    """Modifies the source IP's within a security rule"""
    
    xml_URL = "<PANORAMA/FIREWALL URL>"
    xpath = "<XPATH GOES HERE>"

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



def change_security_rule_service(element, device_group, rule_name, api_key):
    """Modifies the services within a security rule"""
    
    xml_URL = "<PANORAMA/FIREWALL URL>"
    xpath = "<XPATH GOES HERE>"

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



def change_security_rule_application(element, device_group, rule_name, api_key):
    """Modifies the applications within a security rule"""
    
    xml_URL = "<PANORAMA/FIREWALL URL>"
    xpath = "<XPATH GOES HERE>"

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



def change_security_rule_tag(element, device_group, rule_name, api_key):
    """Modifies the tags within a security rule"""
    
    xml_URL = "<PANORAMA/FIREWALL URL>"
    xpath = "<XPATH GOES HERE>"

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



def disable_security_policy(device_group, rule_name, api_key):
    """Disables a security policy"""
    
    xml_URL = "<PANORAMA/FIREWALL URL>"
    xpath = "<XPATH GOES HERE>"
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



def disable_nat_policy(device_group, rule_name, api_key):
    """Disables a NAT policy"""
    
    xml_URL = "<PANORAMA/FIREWALL URL>"
    xpath = "<XPATH GOES HERE>"
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



def change_address_tag(element, address_name, api_key):
    """Modifies the tags within a security rule"""
    
    xml_URL = "<PANORAMA/FIREWALL URL>"
    xpath = "<XPATH GOES HERE>"

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



def change_address_group_tag(element, group_name, api_key):
    """Modifies the tags within a security rule"""
    
    xml_URL = "<PANORAMA/FIREWALL URL>"
    xpath = "<XPATH GOES HERE>"

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



def change_security_log_setting(element, device_group, rule_name, api_key):
    """Modifies the tags within a security rule"""
    
    xml_URL = "<PANORAMA/FIREWALL URL>"
    xpath_start = "<XPATH GOES HERE>"
    device_xpath = "<XPATH GOES HERE>"
    rule_xpath = "<XPATH GOES HERE>"
    #log_xpath = "<XPATH GOES HERE>"

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







#Work in Progress
#####################################################################################################################################################################################
#####################################################################################################################################################################################
#####################################################################################################################################################################################
def create_MDR_blocked_address(api_key):
    """Sample Function used to add address to MDR Blocked IP list. This function is used for example purposes only.

        Parameters:
        -- api_key (string): API key used for authenticating Palo Alto API calls

    """
    
    firewall_URL = "<PANORAMA/FIREWALL URL GOES HERE" #Required 
    device_group = "<DEVICE GROUP>" #Required
    tag = '<TAG>' #Required
    object_IP = '<IP ADDRESS>' #Sample IP Address
    object_description = '<DESCRIPTION>' #Sample description

    #Required - Builds URL with query parameters
    parameters = {
    "location": "device-group",
    "name": object_IP,
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
    
    #Optional
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





def add_address_group_entry(api_key):
    """Modifies the tags within a security rule"""
    
    xml_URL = "<PANORAMA/FIREWALL URL GOES HERE>"
    xpath = "<XPATH GOES HERE>"

    #Builds the HTTP headers
    headers = {
    "X-PAN-KEY": api_key
    }

    params = {
        "type" : "config",
        "action" : "edit",
        "xpath": xpath,
        "element": "<static><member>198.111.56.83</member></static>"
    }
    
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    #POST request with response placed inside a variable 
    response = requests.put(xml_URL, headers=headers, params=params, verify=False)

    if response.status_code == 200:
        print("\nSuccessfully changed tags for the address group: Cisco Core Switches")
        print("Response:", response.text)
        print('\n')
    
    else:
        print("Request Failed with status code:", response.status_code)
        print("Response: ", response.text)



#Can only test if committing
def set_audit_comment(device_group, rule_name, audit_comment, api_key):
    """NEED TO FIGURE OUT HOW TO PROPERLY CALL THIS FUNCTION"""
    
    xml_URL = "<PANORAMA/FIREWALL URL GOES HERE>"
    xpath = "<XPATH GOES HERE>"
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


#Need to work on
def show_security_hit_count(device_group, rule_name, api_key):
    """NEED TO FIGURE OUT HOW TO PROPERLY CALL THIS FUNCTION"""
    
    xml_URL = "<PANORAMA/FIREWALL URL GOES HERE>"
    xpath = "<XPATH GOES HERE>"
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
        print("\nAudit comment added to security rule: " + rule_name)
        print("Response:", response.text)
        print('\n')
    
    else:
        print("Request Failed with status code:", response.status_code)
        print("Response: ", response.text)




