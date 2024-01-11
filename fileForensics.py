#############################################################################
#### IT 2750 - Lab 06                                                       #
#### File Forensics                                                         #
#### Author:                                                                # 
#### !!! IF YOU DO NOT PUT YOUR NAME HERE YOU WILL RECEIVE A ZERO SCORE !!! #
#############################################################################

# Import required modules
from pathlib import Path
import os

###############################################################
# Part 1: Ask the user for the ABSOLUTE path to Bruce Wayne's 
#         folder and save it to a string variable
###############################################################
bruce_wayne_files = input("Enter the ABSOLUTE path to Bruce Wayne's Files: ")


###############################################################
# Part 2: Convert that string to a Path variable
###############################################################
folder_path = Path(bruce_wayne_files)


###############################################################
# Part 3: List all files in the folder and display the name of
#         each file to the user
###############################################################
if folder_path.exists() and folder_path.is_dir():
    print("Files in Bruce Wayne's folder:")
    for file in folder_path.iterdir():
        if file.is_file():
            print(file.name)


###############################################################
# Part 4: Open up each file and look for the string "Batman".
#         If Batman is found, let the user know that 
#         we have found Batman and what file we found the
#         string in
#
#         HINT: Here is an example of looking for a substring
#               within a string varible (we'll call the variable
#               fileContents) (from previous lessons)
#
#         if "Batman" in fileContents:
#            print("Found Batman!!")
###############################################################
    for file in folder_path.iterdir():
        if file.is_file():
            with open(file, 'r') as f:
                file_contents = f.read()
                if "Batman" in file_contents:
                    print(f"Found Batman in {file.name}!!")


