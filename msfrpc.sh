#!/bin/bash

password=$1

msfrpcd -P ${password}

python3 cncserver.py ${password}