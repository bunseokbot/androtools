import sys
import zipfile
import shutil
import commands
import os
import hashlib
import re
import traceback
import json

from lib.dexparser import Dexparser
from lib.CreateReport import HTMLReport
from lib.Certification import CERTParser
import lib.dynamic as dynamic

dexList = [] #dexfile list

#program usage
def usage():
	print "androtools : no file specified"
	print "./androtools <APK_FILE_PATH> <HTML_OUTPUT_FILENAME>"

#program information
def about(apkfile):
	print "Androtools - Android APK Static & Dynamic Analyzer"
	print "Developed by Kim Namjun (Sejong University, Department of Information Security)"
	print "Target APK Path : %s" %apkfile

#filehash extractor
def filehash(apkfile, mode):
	if mode == "md5":
		with open(apkfile, 'rb') as f:
			m = hashlib.md5()
			while True:
				data = f.read()
				if not data:
					break
				m.update(data)
		return m.hexdigest()
	elif mode == "sha1":
		with open(apkfile, 'rb') as f:
			m = hashlib.sha1()
			while True:
				data = f.read()
				if not data:
					break
				m.update(data)
		return m.hexdigest()
	elif mode == "sha256":
		with open(apkfile, 'rb') as f:
			m = hashlib.sha256()
			while True:
				data = f.read()
				if not data:
					break
				m.update(data)
		return m.hexdigest()

	else:
		return ""

#delete temp file directory
def delTemp():
	commands.getoutput("rm -rf temp")

#check target file that this is vaild apk file
def is_android(zfile):
	for fname in zfile.namelist():
		if "AndroidManifest.xml" in fname:
			return True
		elif "resources.arsc" in fname:
			return True
		else:
			pass
	return False

#logging error to error_log.txt
def logError(error_msg):
	f = open('error_log.txt', 'a+')
	f.write('[*] ' + error_msg + '\n')
	f.close()

#extract dex file to temp file
def extractDEX(zfile):
	global dexList
	for fname in zfile.namelist():
		if fname[-4:] == ".dex": #if file extension is dex
			zfile.extract(fname, "temp")
			dexpath = os.path.join("temp", fname)
			dexhash = filehash(dexpath, "md5")
			shutil.move(dexpath, os.path.join("temp", dexhash + ".dex"))
			dexList.append(dexhash + ".dex")

#file resource searching
def fileResource(zfile):
	print "[*] Extracting File Resource Data..."
	extension = {'.apk' : 0, '.png' : 0, '.jpg' : 0, '.xml' : 0, '.mp3' : 0, '.txt' : 0, '.ini' : 0, '.so' : 0}
	keylist = extension.keys()
	soEnvironment = []
	for fname in zfile.namelist():
		if fname[-4:] in keylist:
			extension[fname[-4:]] += 1

		if fname[:4] == "lib/":
			soEnvironment.append(fname.split('/')[1])
			extension[fname[-3:]] += 1

	statistics = []
	for ext in extension.keys():
		if extension[ext] == 0:
			pass
		else:
			tempArr = []
			tempArr.append(ext)
			tempArr.append(str(extension[ext]))
			statistics.append(tempArr)

	return statistics	

#extract string from xml
def extractString(report, apkfile):
	print "[*] Extracting All XML String..."
	stringCmd = "./lib/aapt dump strings %s" %apkfile
	strResult = commands.getoutput(stringCmd).split('\n')
	extractedStr = []
	for xmlstring in strResult:
		if "res/" in xmlstring:
			pass
		else:
			try:
				if len(xmlstring.split(':')[1]) == 0:
					pass
				else:
					extractedStr.append(xmlstring.split(': ')[1])
			except:
				extractedStr.append(xmlstring)

	report.stringinfo(extractedStr)

#get method information from dex
def methodAnalysis(report, string, typeid, method):
	methodArr = []
	for i in range(len(method)):
		(class_idx, proto_idx, name_idx) = method[i]
		class_str = string[typeid[class_idx]]
		name_str  = string[name_idx]
		data = '%s.%s()' % (class_str, name_str)
		methodArr.append(data)
	report.dexmethodinfo(methodArr)

#get dex class filename (.java)
def classExtract(report, string):
	classArray = []
	for dexstr in string:
		if ".java" in dexstr:
			classArray.append(dexstr)
	report.dexclassinfo(classArray)

#get dex adler32 checksum
def checksum(dexmodule):
	return dexmodule.checksum()

#check similarity using ssdeep
def simcheck(apkfile, fuzzyhash):
	print "[*] Checking Similarity..."
	simdata = []
	match = []
	if os.path.exists('sim.txt') == False: #if sim.txt not found?
		print "[*] Creating similarity storage DB.."
		f = open('sim.txt', 'a+')
		f.write('ssdeep,1.1--blocksize:hash:hash,filename\n' + fuzzyhash + '\n')
	else:
		searchQuery = commands.getoutput("ssdeep -m sim.txt " + apkfile).split('\n')
		#print searchQuery
		for query in searchQuery:
			tempArr = []
			try:
				persent = query.split(':')[1].split(' ')[1].replace(')', '%)')
				filename = os.path.basename(query.split(':')[1].split(' ')[0])
				tempArr.append(filename) 
				tempArr.append(persent)
				match.append(tempArr)
			except:
				pass
		f = open('sim.txt', 'a+')
		f.write(fuzzyhash + '\n')

	return match

#find suspicious string in dex and replace if highlight
def findSuspicious(report, stringlist):
	dexstrlist = []
	for i in range(len(stringlist)):
		email 	= re.findall(r'([\w.-]+)@([\w.-]+)', stringlist[i])
		url 	= re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', stringlist[i])
		ip 		= re.findall(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', stringlist[i])

		if email:
			dexstrlist.append(str(email[0][0] + "@" + email[0][1]))
		if url:
			dexstrlist.append(str(url[0]))
		if ip:
			dexstrlist.append(str(ip[0]))

	report.dexstringinfo(dexstrlist)

#parse information from DEX list
def parseDEX(report):
	global dexList
	report.dexinfoHeader()

	for dexfile in dexList:
		parse = Dexparser(os.path.join("temp", dexfile))
		string = parse.string_list()
		typeid = parse.typeid_list()
		method = parse.method_list()
		adler32 = checksum(parse)
		report.dexBasicinfo(dexfile, adler32)
		findSuspicious(report, string)
		#classExtract(report, string)
		#methodAnalysis(report, string, typeid, method)

#get permission information
def permission(report, apkfile):
	print "[*] Extracting Permission Data..."
	permlist = []
	permcmd = "./lib/aapt dump permissions %s" %apkfile
	getperm = commands.getoutput(permcmd).split('\n')
	for perm in getperm:
		if "uses-permission" in perm:
			permlist.append(perm.split(': ')[1])
	report.writePerminfo(permlist)

def nativeparser(solist, report):
	filterList = []
	for sofile in solist:
		with open(os.path.join("temp", sofile[1] + ".so"), 'rb') as f:
			data = f.read()
			email 	= re.findall(r'([\w.-]+)@([\w.-]+)', data)
			url 	= re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', data)
			ip 		= re.findall(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', data)

			if email:
				if str(email[0][0] + "@" + email[0][1]) not in filterList:
					filterList.append(str(email[0][0] + "@" + email[0][1]))
			if url:
				if str(url[0]) not in filterList:
					filterList.append(str(url[0]))
			if ip:
				if str(ip[0]) not in filterList:
					filterList.append(str(ip[0]))
	report.nativeStringinfo(filterList)

#native file information
def nativefile(zfile, report):
	print "[*] Extracting Native File Data..."
	solist = []
	for fname in zfile.namelist():
		if fname[-3:] == ".so":
			tempArr = []
			sofile = os.path.basename(fname)
			source = zfile.open(fname)
			target = file(os.path.join("temp", sofile), "wb")
			with source, target:
				shutil.copyfileobj(source, target)
			sohash = filehash(os.path.join("temp", sofile), "sha1")
			shutil.move(os.path.join("temp", sofile), os.path.join("temp", sohash + ".so"))
			tempArr.append(fname)
			tempArr.append(sohash)
			solist.append(tempArr)

	report.nativeFileinfo(solist)
	nativeparser(solist, report)

#get apk file basic information
def getbasic(apkfile, report):
	print "[*] Extracting Basic APK File Data..."
	filename = os.path.basename(apkfile)
	md5hash = filehash(apkfile, "md5")
	sha1hash = filehash(apkfile, "sha1")
	sha256hash = filehash(apkfile, "sha256")
	filesize = str(os.path.getsize(apkfile) / 1024)
	try:
		fuzzy = commands.getoutput("ssdeep -s " + apkfile).split('\n')[1]
	except:
		print "[*] Fuzzyhash Command not found. Please <brew install ssdeep> to install"
		fuzzy = ""
	report.writeBaseinfo(filename, md5hash, sha1hash, sha256hash, fuzzy.split(',')[0], filesize)
	return fuzzy

#get Certification information
def getCert(zfile, report):
	print "[*] Extracting Certification Data..."
	certlist = []
	certdata = []
	for fname in zfile.namelist():
		if fname[-4:] == ".RSA":
			certfile = os.path.basename(fname)
			source = zfile.open(fname)
			target = file(os.path.join("temp", certfile), "wb")
			with source, target:
				shutil.copyfileobj(source, target)
			certlist.append(certfile)

	for cert in certlist:
		tempArr = []
		c = CERTParser(os.path.join("temp", cert))
		tempArr.append(cert)
		tempArr.append(c.fingerprint())
		tempArr.append(c.issuer())
		tempArr.append(c.starttime())
		certdata.append(tempArr)

	report.writeCERTinfo(certdata)

#get AndroidManifest.xml information
def getManifest(apkfile, report):
	print "[*] Extracting AndroidManifest Data..."
	infocmd = "./lib/aapt dump badging %s" %apkfile
	getinfo = commands.getoutput(infocmd).split('\n')
	apiver = ""
	cputype = ""
	entry = ""
	targetver = ""
	appname = ""
	packname = ""
	entry = ""
	for info in getinfo:
		data = info.split(':')
		if data[0] == "sdkVersion":
			apiver = data[1].replace('\'', '')
		
		if data[0] == "targetSdkVersion":
			targetver = data[1].replace('\'', '')
		
		if data[0] == "application-label":
			try:
				appname = data[1].replace('\'', '')
			except:
				appname = data[1]
		
		if data[0] == "package":
			packname = data[1].split('\'')[1]

		if data[0] == "launchable-activity":
			entry = data[1].split('\'')[1]

		if data[0] == "native-code":
			for cpu in data[1].split('\''):
				cputype += cpu + " " 

	report.writeManifestinfo(apiver, cputype, targetver, appname, packname, entry)
	return [packname, entry]

#dynamic analysis
def dynamicAnalysis(report, apkfile, packname, entry):
	print "[*] Dynamic Analysis start!"
	anal_result = dynamic.main(apkfile, packname, entry)
	result = json.loads(anal_result)

	try:
		report.datasectioninfo(result['filetag']['startCreate'], result['filetag']['endCreate'])
	except:
		pass

	try:
		report.logcatinfo(result['logtag'])
	except:
		pass

	try:
		report.packetinfo(result['packettag']['packet'], result['timeline']['ipList'])
	except:
		pass

	print "[*] Dynamic Analysis end!"

#program entry point
def main(apkfile, output):
	try:
		about(apkfile) #program information
		isVaild = zipfile.is_zipfile(apkfile) #check vaild zip container
		if isVaild:
			zfile = zipfile.ZipFile(apkfile)
			isAndroid = is_android(zfile) #check vaild android apk file
			if isAndroid:
				print "[*] Analysis start!"

				#setting HTML Report
				report = HTMLReport(output)
				report.header()
				report.style()
				report.bodystart()

				fuzzy = getbasic(apkfile, report)
				extractDEX(zfile) #extract dex file
				filetype = fileResource(zfile) #analyze file resources
				simresult = simcheck(apkfile, fuzzy) #similarity check
				report.writeFileinfo(filetype, simresult)

				xmlinfo = getManifest(apkfile, report)
				permission(report, apkfile)

				getCert(zfile, report)

				parseDEX(report)

				extractString(report, apkfile)

				nativefile(zfile, report)

				dynamicAnalysis(report, apkfile, xmlinfo[0], xmlinfo[1])

				report.endbody()
				del report

			else:
				print "[*] Sorry, We can\'t analyze this file"
		else:
			print "[*] Sorry, We can\'t analyze this file"
		delTemp()
		print "[*] Analysis complete!"
	except Exception, e:
		logError(str(traceback.format_exc()))
		print "[*] Androtools Exception - Error logged!"

if __name__ == '__main__':
	try:
		main(sys.argv[1], sys.argv[2])
	except:
		usage()