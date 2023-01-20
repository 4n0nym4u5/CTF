#!/usr/bin/python2

from PIL import Image


def make_pixels(data):
	data = data.replace(",", "(102,0,204)")
	data = data.replace("-", "(0,255,255)")
	data = data.replace(">", "(255,0,0)")
	data = data.replace(")", "),")
	data = data[:-1]
	return data

def make_image(data, path=None):
	# print(data)
	im = Image.new("RGB", (50,50))
	im.putdata(data)
	if path == None:
		im.save("/home/init0/pix.png")
	im.save(path)
	return path