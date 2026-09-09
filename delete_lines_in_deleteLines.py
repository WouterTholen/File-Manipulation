import os
from shutil import rmtree
from pathlib import Path


counter = 0

def handler(func, path, exc_info):
    counter = counter - 1
    print("We got the following exception")
    print(exc_info)


with open("deleteLines.txt", 'r', encoding='utf-8') as file:
	for line in file:
		line = Path(line.strip())
		counter +=1
		print("Deleting: " + str(line))
		try:
#			rmtree(line, ignore_errors=False, onerror=handler)
			os.remove(line)
		except:
			print("Trouble deleting" + str(line))

			
print("Removed " , counter , " files")