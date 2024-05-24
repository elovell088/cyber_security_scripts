#Functions for manipulating files systems

import shutil
import platform
import os
import time
from pathlib import Path

def copyFiles(passed_folder_to_copy, passed_copy_to_folder ):
    """Function that validates file paths and executes the executeFileCopy() Function.
    Arguments:
        passed_folder_to_copy {String Value} -- String value that consists of the file path for the folder to copy - without root path
        passed_copy_to_folder {String Value} -- String value that consists of the file path for the folder to COPY TO - without root path
    
    Returns:
        None -- Directly copies contents of one file into a new folder"""
    
    #Creates paths based off string value parameters 
    my_source_path = getPath(passed_folder_to_copy)
    my_destination_path = getPath(passed_copy_to_folder)

    #Placing os.path instances in variables for easier readability. Holds True or False if path exists or not.
    source_path_exists = os.path.exists(my_source_path) and os.path.isdir(my_source_path)
    destination_path_exists = os.path.exists(my_destination_path) and os.path.isdir(my_destination_path)
    
    #If source path doesn't exist, print statement and terminate method.
    if not source_path_exists:
        print("\nThe source path does not exist.\n")
    else:
        #If source exists but destinations doesn't, TRY to create the folder, create log, and copy the files.
        if not destination_path_exists:
            try:
                createFolder(passed_copy_to_folder)
                createLogFile(my_destination_path)
                executeFileCopy(my_source_path, my_destination_path)
            except:
                #If creating the folder fails, just return None
                print("\nDestination folder does not exist. Failed to create Directory.\n")
                return None
        else:
            #If both paths exist, create the log file and copy the files
            createLogFile(my_destination_path)
            executeFileCopy(my_source_path, my_destination_path)



def createFolder(passed_string):
    """Function that validates file paths and executes the executeFileCopy() Function.
    Arguments:
        passed_string {String Value} -- String value that consists of the file path
        
    Returns:
        None -- Creates a new directory in the File system"""
    
    #Get path
    my_path = getPath(passed_string)
    
    #Make Directory
    os.makedirs(my_path)
    print("Folder: " + my_path + " was created.")


def createLogFile(passed_destination_path):
    """Function that creates a log file
    Arguments:
        passed_destination_path {String Value} -- String value that consists of the file path to the destination
        
    Returns:
        None -- Creates file called log.txt and places it in the file system"""
    
    #Change to destination directory 
    os.chdir(passed_destination_path)
    log_string = "Log File: " + str(time.time()) + "\n\n1.) " + passed_destination_path + " was created successfully.\n"
    log_file = 'log.txt'
    
    #Create File
    with open(log_file, 'w') as text_file:
        text_file.write(log_string)


def executeFileCopy(passed_source_path, passed_destination_path):
    """Function that performs the execution of copying files to new folder.
    Arguments:
        passed_source_path {String Value} -- String value that consists of the file path for the folder to copy
        passed_destination_path {String Value} -- String value that consists of the file path for the folder to COPY TO
    
    Returns:
        None -- Directly copies contents of one file into a new folder"""
    
    #Change directory
    os.chdir(passed_source_path)
    
    #Put the contents of the source directory into a list
    file_list = os.listdir(passed_source_path)
    print("\nFile Contents: " + passed_source_path)

    #For each file in the source directory
    log_count = 2
    for file_item in file_list:
        os.chdir(passed_source_path)
        print(file_item)

        #os.path instances are placed into variable for easier readability
        sourceFile = os.path.join(passed_source_path, file_item)
        sourceIsFile = os.path.isfile(sourceFile)
        sourceIsDir = os.path.isdir(sourceFile)
        sourceToLarge = validateFileSize(passed_source_path, file_item)

        #If file item is a file and not over 1Gb, copy file, write to log
        if sourceIsFile and not sourceToLarge:
            shutil.copy2(file_item, passed_destination_path)
            copy_success_string = "\n" + str(log_count) + ".) " + file_item + " was copied successfully to " + passed_destination_path + "\n"
            writeToLog(copy_success_string, passed_destination_path)
        
        #If the file item is a file but too large, skip it, write to log
        elif sourceIsFile and sourceToLarge:
            file_to_large_string = "\n" + str(log_count) + ".) " + sourceFile + " was passed over for being over 1Gb in size." + "\n"
            writeToLog(file_to_large_string, passed_destination_path)
        
        #If the file item is a directory, skip it, write to log
        elif sourceIsDir:
            skip_folder_string = "\n" + str(log_count) + ".) " + sourceFile + " was skipped. Path is a directory." + "\n"
            writeToLog(skip_folder_string, passed_destination_path)

        log_count += 1



def getPath(passed_folder):
    """Function that generates determines the os type and comebines the proper root path with the rest of the path
    Arguments:
        passed_folder {String Value} -- String value containing file path without the root portion
    
    Returns:
        final_filepath {String Value} -- String value containing the absolute file path"""
    
    #Place platform information into a variable
    my_system = platform.system()
    
    #If windows root is c:\, if other, root is /
    if my_system == "Windows":
        root_fs = "C:\\"
    else:
        root_fs = "/"
    
    #Create absolute path
    final_filepath = os.path.join(root_fs, passed_folder)  
    
    return final_filepath



def validateFileSize(passed_source_path, passed_file_item):
    """Function that validates the 
    Arguments:
        passed_source_path {String Value} -- String value that consists of the file path for the folder to copy
        passed_file_item {String Value} -- String value that containing the name of the file for size inspection
    
    Returns:
        True -- If the file is too large || False -- IF the file size is valid"""

    #Get the size of each file
    temp_file_size = os.path.getsize(os.path.join(passed_source_path, passed_file_item))
    temp_file_divide = temp_file_size / 1000000

    #If the file size is in the bytes range
    if temp_file_divide < 1:
        return False
    
    #If the file is in bytes or megabytes range
    elif temp_file_divide > 1 and temp_file_divide < 1000:
        return False
    
    #If the file is greater than 1000mb or 1Gb 
    else:
        return True



def writeToLog(passed_string, passed_destination_path):
    """Function that creates a log file
    Arguments:
        passed_string {String Value} -- String value that consists of the string to write to the log file
        passed_destination_path {String Value} -- String value that consists of the file path to the destination
        
    Returns:
        None -- Creates file called log.txt and places it in the file system"""
    
    #Change directory to destination
    os.chdir(passed_destination_path)
    log_file = 'log.txt'
    
    #Write contents to log
    with open(log_file, "a") as text_file:
        text_file.write(passed_string)
