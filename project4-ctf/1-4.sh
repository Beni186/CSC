#!/usr/bin/env bash

binwalk -e meow.jpg
cat _meow.jpg.extracted/flag.txt | grep -o -E 'FLAG\{.*\}'