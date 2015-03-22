#-*-coding: utf-8-*-
import os
import sys
import commands
import time
import json
import threading
import dpkt
import socket
import hashlib
import zipfile
import subprocess
import datetime
import os
import signal

packname = "" #package name
entrypoint = "" #entry activity

"""
Error Code
10000 - APK File not found
10001 - VM Not found
10002 - APK Install error
10003 - Not supported CPU_ABI
"""

sdkDir = "./lib/adb "

afterSection = []
endSection = []

logData = []

timeLog = []

class Object:
	def to_JSON(self):
		return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)

fileStatus = Object()
packetObject = Object()
timelineObject = Object()

#execute and filter the result of logcat
def executelog(command, timeout, packname):
	starttime = datetime.datetime.now()
	proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	proc2 = subprocess.Popen(["./lib/proclogcat", packname], stdin=proc.stdout, stdout=subprocess.PIPE)
	while proc.poll() is None:
		time.sleep(0.1)			
		now = datetime.datetime.now()
		if (now - starttime).seconds > timeout:
			os.kill(proc.pid, signal.SIGKILL)
			os.waitpid(-1, os.WNOHANG)
	#proc2 = subprocess.Popen(["./lib/proclogcat", packname], stdin=proc.stdout, stdout=subprocess.PIPE)
	return proc2.stdout.read()

#execute command with timeout
def executeCmd(command, timeout):
	starttime = datetime.datetime.now()
	proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	while proc.poll() is None:
		time.sleep(0.1)			
		now = datetime.datetime.now()
		if (now - starttime).seconds > timeout:
			os.kill(proc.pid, signal.SIGKILL)
			os.waitpid(-1, os.WNOHANG)
	return proc.stdout.read()
	
def packet():
	global packetObject, timelineObject
	execute = executeCmd([sdkDir.replace(" ", ""), "shell", "tcpdump", "-w", "/sdcard/packet.pcap", "-i", "eth1"], 15) 
	#commands.getoutput("timeout 15 " + sdkDir + "shell tcpdump -w /sdcard/packet.pcap -i eth1")
	packetData = []
	ipData = []
	pulldata = commands.getoutput(sdkDir + "pull /sdcard/packet.pcap")
	fname = str(int(time.time())) + ".pcap"
	mvpacket = commands.getoutput("mv packet.pcap " + fname)
	f = open(fname)
	pcap = dpkt.pcap.Reader(f)
	
	for ts, buf in pcap:
		try:
			packetInfo = []
			eth = dpkt.ethernet.Ethernet(buf)
			ipHeader = eth.data
			packetTime = int(ts)
			sourceIP = socket.inet_ntoa(ipHeader.src)
			destinIP = socket.inet_ntoa(ipHeader.dst) 

			packetInfo.append(str(packetTime))
			packetInfo.append(sourceIP)
			packetInfo.append(destinIP)
			packetData.append(packetInfo)
			if sourceIP not in ipData:
				ipData.append(sourceIP)
			if destinIP not in ipData:
				ipData.append(destinIP)
		except:
			pass

	packetObject.packet = packetData
	timelineObject.ipList = ipData
	os.remove(fname)

def logAnalyzer(logdata):
	logTab = logdata.split("\n")
	for log in logTab:
		log = log.replace("\r", "")
		if "dalvikvm" not in log:
			if log not in logData:
				if len(log) != 0:
					logData.append(log)

def detectUIAutomator():
	uiauto = commands.getoutput(sdkDir + " push UIAutomator.jar /data/local/tmp")

def readSection(packname):
	read = commands.getoutput(sdkDir + "shell find /data/data/" + packname + "/*")
        section = read.split("\n")
	return section 

def startForensic(filehash):
	global endSection, afterSection, packname
	#executeApp = commands.getoutput(sdkDir + "shell am start -n " + packname + "/" + entrypoint)
	executeApp = executeCmd([sdkDir.replace(" ", ""), "shell", "am", "start", "-n" , packname + "/" + entrypoint], 5)
	time.sleep(1)
	afterSection = readSection(packname)
	automaticAction = commands.getoutput(sdkDir + "shell uiautomator runtest UIAutomator.jar -c main#automatedAction -e packname " + packname)
	endSection = readSection(packname)
	logData = executelog([sdkDir.replace(" ", ""), "logcat"], 5, packname)
	logAnalyzer(logData)

	delete = commands.getoutput(sdkDir + "uninstall " + packname)
	if "Failure" in delete:
		disableDeviceAdmin = commands.getoutput(sdkDir + "shell uiautomator runtest UIAutomator.jar -c main#disableDeviceAdmin -e packname " + packname)
		reDelete = commands.getoutput(sdkDir + "uninstall " + packname)

def main(apkfile, packageName, startpoint):
	global screenLog, packetData, afterSection, sdkDir, packname, entrypoint

	packname = packageName
	entrypoint = startpoint
	
	report = Object()
	
	sectionList = []

	status = commands.getoutput(sdkDir + "devices")
	devicelist = status.replace("List of devices attached", "").split("\n")

	if len(devicelist) < 3:
		return "{\"\"\":\"Analysis Machine Not found\",\"errorcode\":\"10001\"}"

	else:
		cacheDel = commands.getoutput(sdkDir + "shell \"rm -rf /data/data/" + packname + "\"") #cache delete
		install = commands.getoutput(sdkDir + "install " + apkfile)
		
		if "Failure" in install:
			if "CPU_ABI" in install: #if CPU_ABI is not support x86 
				return "{\"message\":\"not supported CPU_ABI\",\"errorcode\":\"10003\"}" 
			else:
				f = open('errorlog.txt', 'a')
				f.write(install + '\n')
				f.close()
				return "{\"message\":\"APK Install error\",\"errorcode\":\"10002\"}"
		elif "Success" in install:
			with open(apkfile, 'rb') as f:
				sha1 = hashlib.sha1()
				while True:
					data = f.read()
					if not data:
						break
					sha1.update(data)

			filehash = sha1.hexdigest()
			detectUIAutomator()

			ready = commands.getoutput(sdkDir + "shell uiautomator runtest UIAutomator.jar -c main#readyForAnalysis")
			time.sleep(2)
			
			beforeSection = readSection(packname)
			
			packetThread = threading.Thread(target=packet)
			actionThread = threading.Thread(target=startForensic, args=(filehash, ))
			packetThread.start()				
			actionThread.start()		
			packetThread.join()
			actionThread.join()
			
			
			for data in afterSection:
				if data not in beforeSection:
					sectionList.append(data.replace("\r", ""))
			fileStatus.startCreate = sectionList	
			
			endList = [] #initialize section list
			
			for data in endSection:
				if data not in afterSection:
					endList.append(data.replace("\r", ""))

			fileStatus.endCreate = endList
			report.filetag = fileStatus
			report.logtag  = logData
			report.packettag = packetObject
			report.timeline = timelineObject

			cacheDel = commands.getoutput(sdkDir + "shell \"rm -rf /data/data/" + packname + "\"") #cache delete

			return report.to_JSON()	
			#print nativeTarget
		
		else:
			return "{\"error_msg\":\"APK Install error\",\"errorcode\":\"10002\"}"