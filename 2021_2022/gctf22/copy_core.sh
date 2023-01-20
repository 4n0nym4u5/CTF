#!/bin/bash

sudo cp -f /var/lib/systemd/coredump/* crashes/$1
sudo rm -f /var/lib/systemd/coredump/*