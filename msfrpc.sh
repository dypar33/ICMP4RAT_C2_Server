#!/bin/bash

password=$1

msfconsole << EOF
load msgrpc ${password}
EOF

msfrpcd -P ${password}

python3 cncserver.py ${password}