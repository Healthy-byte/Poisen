#!/usr/bin/python3

from socket import *
import os
from datetime import datetime

server_port = 80
try:
    server_socket = socket(AF_INET,SOCK_STREAM)
    server_socket.bind(('',server_port))
    server_socket.listen(1)
    print("The server is ready to receive")
except OSError:
    print("Port is already in use, trying a port number higher")
    server_port += 1
    print ("Port number is now: ", server_port)
    server_socket = socket(AF_INET,SOCK_STREAM)
    server_socket.bind(('',server_port))
    server_socket.listen(1)
    print("The server is ready to receive")

while True:
    conn_socket,client_address = server_socket.accept()
    ip_address, port_number = client_address
    print("IP and PORT from client: ", ip_address, port_number)
    modified_message =conn_socket.recv(2048).decode().upper()
    #conn_socket.send(modified_message.encode())
    #print("connection received from {}, and {} is sent back".format(client_address[1],modified_message))
    print (modified_message)

    ###Variabler###
    http_liste = modified_message.split('\r\n')
    file_path = os.path.dirname(os.path.abspath(__file__))
    list_files = os.listdir(file_path)
    req_headers = dict()
    http_200 = """HTTP/1.1 200 OK
Content-Type: text/html\r\n\r\n"""
    http_404 ="HTTP/1.1 404 Not Found\r\n\r\n" 
    http_400 = "HTTP/1.1 400 Bad Request\r\n\r\n"
    log_file = os.path.join(file_path, "log.txt")
    date = datetime.now().strftime("%Y_%m_%d %I:%M:%S %p")
    ###Variabler### 

    ###HVIS HTTP/1.1 og GET i HTTP request###
    if "GET" in http_liste[0] and "HTTP/1.1" in http_liste[0]:
        print("Good request!")
        print ("GET request performed \n")

        ###Smid req headers ind i dictionary###
        for i in http_liste[1:]:
            splittet_værdi = i.split(": ")
            if splittet_værdi[0] != "" and splittet_værdi[1] != "":
                req_headers[splittet_værdi[0]] = splittet_værdi[1]
        print (req_headers)

        ###INDEX.TXT###
        http_method = http_liste[0].split(" ")
        if http_method[1] == "/FACEBOOK.HTML" or http_method[1] == "/":

            conn_socket.send(http_200.encode())
            ###Kig i index.html filen###
            with open(os.path.join(file_path, "facebook.html"), "r") as index_file:
                for lines in index_file.readlines():
                    conn_socket.send(lines.encode())

            ###Append til log fil###
            size = os.path.getsize(os.path.join(file_path, "facebook.html"))
            with open(log_file, "a") as log_file:
                log_file.writelines(f"{ip_address} -- [{date}] USERAGENT: {req_headers['USER-AGENT']} '{http_liste[0]}' RESPONSE: {http_200} {size}\n\n")


        ###ALT ANDET###
        else:
            conn_socket.send(http_404.encode())
            ###Kig i index.html filen###
            with open(os.path.join(file_path, "404notfound.html"), "r") as file404:
                for lines in file404.readlines():
                    conn_socket.send(lines.encode()) 
                    conn_socket.send("<br>".encode())

            ###Append til log fil###
            with open(log_file, "a") as log_file:
                log_file.writelines(f"{ip_address} -- [{date}] USERAGENT: {req_headers['USER-AGENT']} '{http_liste[0]}' RESPONSE: {http_404}\n")

    
    ###Hvis det ikke er GET request###
    else:
        conn_socket.send(http_400.encode())
        with open(os.path.join(file_path, "400badreq.html"), "r") as file400:
            for lines in file400.readlines():
                conn_socket.send(lines.encode())
                conn_socket.send("<br>".encode())

        ###Append til log fil###
        with open(log_file, "a") as log_file:
            log_file.writelines(f"{ip_address} -- [{date}] -- {http_404}")
    
    conn_socket.close()
server_socket.close()
