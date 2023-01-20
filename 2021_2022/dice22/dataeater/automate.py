#!/usr/bin/python3


from selenium import webdriver
from time import sleep

url = "https://flagle.mc.ax/"
all_funcs = ["ABORT", "FS", "HEAP", "HEAP8", "IDBFS", "a", "abort", "asm", "atob", "blur", "btoa", "c", "ccall", "cwrap", "err", "exit", "fetch", "find", "focus", "fs", "name", "open", "out", "quit_", "read_", "run", "self", "stop", "top", "_a", "_free", "Array", "Attr", "Audio", "Blob", "CSS", "Cache", "Date", "Error", "Event", "File", "HID", "Image", "Ink", "Intl", "JSON", "Lock", "Map", "Math", "NaN", "Node", "Proxy", "Range", "Set", "Text", "Touch", "URL", "USB", "XRRay", "eval", "event", "isNaN"]

dk = webdriver.Firefox()

ape = "dice{F!3lD d0Nu7 VVVVV m@x!M T$r3}"

for funcs in all_funcs:
	dk.get(url)
	dk.find_element_by_xpath("/html/body/div/div[1]/input[1]").send_keys("dice{")
	dk.find_element_by_xpath("/html/body/div/div[1]/input[2]").send_keys("F!3lD")
	dk.find_element_by_xpath("/html/body/div/div[1]/input[3]").send_keys("d0Nu7")
	dk.find_element_by_xpath("/html/body/div/div[1]/input[4]").send_keys(funcs)
	dk.find_element_by_xpath("/html/body/div/div[1]/input[5]").send_keys("m@x!M")
	dk.find_element_by_xpath("/html/body/div/div[1]/input[5]").send_keys("T$r3}")
	dk.find_element_by_xpath('//*[@id="guess-button"]').click()
	# sleep(1)
	try:
		dk.find_element_by_xpath("/html/body/div/div[2]/input[4]").send_keys("mmmm")
	except:
		print("SOLVED")
		print(funcs)
		input("AAAA : ")
