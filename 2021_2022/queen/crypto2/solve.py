#!/usr/bin/env python3
from base64 import b64decode
from Crypto.Util.number import *
from Crypto.PublicKey import RSA
from rootkit import *

# c=open('mystery.txt','r').read()
# c=b64decode(c)
# c=bytes_to_long(c)
c=7478810753691132671580565299658303764351660917655357862840105779412449233704541951152791374542580497016306246747256965500586061764066958367513228914853681416102277109547647441216128159955496879255783486921958781076094609550337270798419165344508510577820935765004623695436929048717939212958345449247834586144588114745622567068134093457709486514476014490168726268373870887134395935891980281885544428835321457499009429918425232814547919791024050340333257787158882123059020377208184883303618085612014551648807757376339017531150962672154405328335629281548927393398509074823234306691628571522232519911490816233620680694644
# print(c)
n=25906459181398984055427328184118799767028131331416776156085601528309110406939999682859379829580054574348486089195717497283068229652632312042695540681788729368341080453809920783086728527769806643263577310685174064814035196526021813321205518964783548926983194338993332755599865351519052308842097159708495427548739127167031108509473450393158614285632439415479776636824849702248010583948792290341330621281635021999066630526149053988455412181940582294649159198245618704684744284777207526647892781156664740212414409172180504207163173824860447524478762311642419151599899624550023607097817148633921347174614630107927022992473
e=65537
p=147763690849150867668225909469550433915451732812463057700984569348470253956194816406951574728889706783894785686020012100588052689320692584241194441102306664861087263417689874062764278453049583722940577602045732615047554285117930803297120866855129431558042684619199933145634615860792724440681809733506643143827
q=175323579375439355271067762791797570532327618905238153569106939865810515426195444129569514172323381418275130113304584918382539461249836590401476762173083711488347557377316041604414956494612922763528717954203932654977534635925919801687408066965455169210358420975001566564559944039223342904162696905475355996899
phi = ( q - 1 ) * ( p - 1 )
d = inverse( e, phi )
m = pow( c, d, n )
print(long_to_bytes(m))