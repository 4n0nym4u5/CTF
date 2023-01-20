#!/bin/bash
exec 2>/dev/null
cd /home/init0/share/bkup/CTF/ascs/distfiles
timeout 600 /home/carot/proxy.py
