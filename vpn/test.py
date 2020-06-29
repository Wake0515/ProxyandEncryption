import os

os.system('python server.py -s 127.0.0.1:8489 -p password -e AES-GCM')
os.system('python client.py -c 127.0.0.1:8488 -s 127.0.0.1:8489 -p password -e AES-GCM')
