#!/usr/bin/env python3

import subprocess
import base64
import re

def run_strings_command(file_path):
    # Execute the strings command and capture its output
    result = subprocess.run(['strings', file_path], capture_output=True, text=True)
    output = result.stdout.strip()
    return output

def filter_base64_strings(strings):
    base64_pattern = r'[A-Za-z0-9+/]+={0,2}'
    base64_strings = re.findall(base64_pattern, strings)
    return base64_strings

def base64_decode_string(encoded_string):
    try:
        decoded_string = base64.b64decode(encoded_string).decode()
        return decoded_string
    except:
        return None

# Usage example
file_path = 'string'
strings_output = run_strings_command(file_path)
base64_strings = filter_base64_strings(strings_output)

for encoded_string in base64_strings:
    decoded_string = base64_decode_string(encoded_string)
    if decoded_string is not None:
        flag_pattern = r'FLAG\{[^}]+\}'
        match = re.search(flag_pattern, decoded_string)
        if(match):
            print(match.group())
import base64
