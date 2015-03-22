class HTMLReport:
	def __init__(self, fname):
		f = open(fname, 'w+')
		self.f = f

	def header(self):
		headdata = "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">"
		headdata += "<html xmlns=\"http://www.w3.org/1999/xhtml\" lang=\"en\">" 
		headdata += "<head>"
		headdata += "<meta http-equiv=\"content-type\" content=\"text/html; charset=utf-8\"/>" 
		headdata += "<meta name=\"description\" content=\"This document supports Android Malware Analysis Report\"/>" 
		headdata += "<meta name=\"author\" content=\"Kim Namjun\"/>" 
		headdata += "<meta name=\"reply-to\" content=\"admin@smishing.kr(Namjun, Kim)\"/>" 
		headdata += "<title>Android Malware Analysis Report</title>" 
		headdata += "</head>"

		self.f.write(headdata)

	def style(self):
		styledata = "<style>body p { margin: center;font-size: 21px;line-height:200%;} "
		styledata += "body { margin: 0; padding: 0; background-color: #FFFFFF; font-family: verdana, arial; } "
		styledata += "body div.center { font-size: 18px; text-align:center; line-height: 100%;}"
		styledata += "table.dir { width: 980px; border: 1px solid #c0c0c0; background: #f0f0f0; margin-bottom: 10px; }"
		styledata += "table.dir th { padding: 10px 12px 10px 12px; color: #203040; background: #d0e0f0; text-align: left; } "
		styledata += "table.dir td { padding: 2px 12px 2px 12px; color: #202020; text-align: left; }"
		styledata += ".hd { padding: 2px 12px 2px 12px; color: #203040; background: #d0e0f0; text-align: center; width: 190px; }"
		styledata += "div.border { text-align: center;font-size: 10pt; }</style>"

		self.f.write(styledata)

	def bodystart(self):
		bodystart = "<body> <p style=\"text-align:center;line-height:200%;\">Android Malware Analysis Report</p> <div class=\"center\">"
		self.f.write(bodystart)

	def writeBaseinfo(self, fname, md5, sha1, sha256, fuzzy, filesize):
		baseinfo = "<p style=\"text-align:center;line-height:100%;\">"
		baseinfo += "<span style=\"font-size:15.0pt;line-height:100%\">1. APK Basic Information</span>"
		baseinfo += "</p>"
		baseinfo += "<table class=\"dir\" border=\"0\" style=\"line-height:100%;word-break:break-all;margin: 0 auto;\">"
		baseinfo += "<tbody>"
		baseinfo += "<tr><td class=\"hd\">Filename</td><td>" + fname + "</td></tr>" 
		baseinfo += "<tr><td class=\"hd\">MD5 Hash</td><td>" + md5 + "</td></tr>" 
		baseinfo += "<tr><td class=\"hd\">SHA1 Hash</td><td>" + sha1 + "</td></tr>" 
		baseinfo += "<tr><td class=\"hd\">SHA256 Hash</td><td>" + sha256 + "</td></tr>" 
		baseinfo += "<tr><td class=\"hd\">Fuzzyhash</td><td>" + fuzzy + "</td></tr>" 
		baseinfo += "<tr><td class=\"hd\">Filesize</td><td>" + filesize + "KB</td></tr>" 
		baseinfo += "</tbody></table><br><br>"
		self.f.write(baseinfo)

	def writeFileinfo(self, statdata, simcheck):
		simdata = ""
		for sim in simcheck:
			simdata += sim[0] + " " + sim[1] + "<br>"

		statistics = ""
		for stat in statdata:
			statistics += stat[0] + " : " + stat[1] + "<br>"

		baseinfo = "<p style=\"text-align:center;line-height:100%;\">" 
		baseinfo += "<span style=\"font-size:15.0pt;line-height:100%\">2. File Analysis</span>" 
		baseinfo += "</p>" 
		baseinfo += "<table class=\"dir\" border=\"0\" style=\"line-height:100%;word-break:break-all;margin: 0 auto;\">" 
		baseinfo += "<tbody>"
		baseinfo += "<tr><td class=\"hd\">Filetype statistics</td><td>" + statistics + "</td></tr>" 
		baseinfo += "<tr><td class=\"hd\">Similarity Check</td><td>" + simdata + "</td></tr>" 
		baseinfo += "</tbody></table>"
		baseinfo += "<br><br>"
		self.f.write(baseinfo)

	def writeManifestinfo(self, apiver, cputype, targetver, appname, packname, entry):
		manifestinfo = "<p style=\"text-align:center;line-height:100%;\">" 
		manifestinfo += "<span style=\"font-size:15.0pt;line-height:100%\">3. AndroidManifest Information</span>" 
		manifestinfo += "</p>" 
		manifestinfo += "<table class=\"dir\" border=\"0\" style=\"line-height:100%;word-break:break-all;margin: 0 auto;\">" 
		manifestinfo += "<tbody>" 
		manifestinfo += "<tr><td class=\"hd\">SDK Version</td><td>" + apiver + "</td></tr>" 
		manifestinfo += "<tr><td class=\"hd\">Targeted SDK Ver</td><td>" + targetver + "</td></tr>" 
		manifestinfo += "<tr><td class=\"hd\">Application Name</td><td>" + appname + "</td></tr>" 
		manifestinfo += "<tr><td class=\"hd\">Supported CPU Type</td><td>" + cputype + "</td></tr>" 
		manifestinfo += "<tr><td class=\"hd\">Package Name</td><td>" + packname + "</td></tr>"
		manifestinfo += "<tr><td class=\"hd\">Entry Activity</td><td>" + entry + "</td></tr>" 
		manifestinfo += "</tbody></table><br>"
		self.f.write(manifestinfo)

	def writePerminfo(self, permlist):
		perminfo = "<p style=\"text-align:center;line-height:100%;\">"
		perminfo += "<span style=\"font-size:13.0pt;line-height:100%\">- Permission Information -</span>"
		perminfo += "</p>" 
		perminfo += "<table class=\"dir\" border=\"0\" style=\"line-height:100%;word-break:break-all;margin: 0 auto;\">"
		perminfo += "<tbody>" 
		for permname in permlist:
			perminfo += "<tr><td>" + permname + "</td></tr>"
		perminfo += "</tbody></table><br><br>"
		self.f.write(perminfo)

	def writeCERTinfo(self, certdata):
		certinfo = "<p style=\"text-align:center;line-height:100%;\">" 
		certinfo += "<span style=\"font-size:15.0pt;line-height:100%\">4. Certification Information</span>" 
		certinfo += "</p>" 
		for cert in certdata:
			certinfo += "<table class=\"dir\" border=\"0\" style=\"line-height:100%;word-break:break-all;margin: 0 auto;\">" 
			certinfo += "<tbody>" 
			certinfo += "<tr><td class=\"hd\">Cert Filename</td><td>" + cert[0] + "</td></tr>" 
			certinfo += "<tr><td class=\"hd\">Fingerprint</td><td>" + cert[1] + "</td></tr>" 
			certinfo += "<tr><td class=\"hd\">Issuer</td><td>" + cert[2] + "</td></tr>" 
			certinfo += "<tr><td class=\"hd\">Issue Time</td><td>" + cert[3] + "</td></tr>" 
			certinfo += "</tbody></table><br>"
		certinfo += "<br>"
		self.f.write(certinfo)

	def dexinfoHeader(self):
		dexinfo = "<p style=\"text-align:center;line-height:100%;\"><span style=\"font-size:15.0pt;line-height:100%\">5. DEX File Information</span></p>"
		self.f.write(dexinfo)

	def dexBasicinfo(self, dexname, checksum):
		dexbasicinfo = "<p style=\"text-align:center;line-height:100%;\">"
		dexbasicinfo += "<span style=\"font-size:13.0pt;line-height:100%\">- Basic Information -</span>"
		dexbasicinfo += "</p>" 
		dexbasicinfo += "<table class=\"dir\" border=\"0\" style=\"line-height:100%;word-break:break-all;margin: 0 auto;\">"
		dexbasicinfo += "<tbody>" 
		dexbasicinfo += "<tr><td class=\"hd\">DEX Filename</td><td>" + dexname + "</td></tr>"
		dexbasicinfo += "<tr><td class=\"hd\">Checksum</td><td>" + checksum + "</td></tr>"
		dexbasicinfo += "</tbody></table><br>"
		self.f.write(dexbasicinfo)

	def dexstringinfo(self, string):
		dexstringinfo = "<p style=\"text-align:center;line-height:100%;\">" 
		dexstringinfo += "<span style=\"font-size:13.0pt;line-height:100%\">- Suspicious String (IP, URL, Email) -</span>"
		dexstringinfo += "</p>"
		dexstringinfo += "<table class=\"dir\" border=\"0\" style=\"line-height:100%;word-break:break-all;margin: 0 auto;\">"
		dexstringinfo += "<tbody>"

		for dexstr in string:
			dexstringinfo += "<tr><td>" + dexstr + "</td></tr>"
			
		dexstringinfo += "</tbody></table><br>"
		self.f.write(dexstringinfo)

	def dexclassinfo(self, javaclass):
		dexstringinfo = "<p style=\"text-align:center;line-height:100%;\">"
		dexstringinfo += "<span style=\"font-size:13.0pt;line-height:100%\">- Class Information -</span>" 
		dexstringinfo += "</p>" 
		dexstringinfo += "<table class=\"dir\" border=\"0\" style=\"line-height:100%;word-break:break-all;margin: 0 auto;\">"
		dexstringinfo += "<tbody><tr><th class=\"hd\">Java File</th></tr>"

		for dexstr in javaclass:
			dexstringinfo += "<tr><td>" + dexstr + "</td></tr>"
			
		dexstringinfo += "</tbody></table><br>"
		self.f.write(dexstringinfo)

	def dexmethodinfo(self, method):
		dexstringinfo = "<p style=\"text-align:center;line-height:100%;\">" 
		dexstringinfo += "<span style=\"font-size:13.0pt;line-height:100%\">- Method Information -</span>"
		dexstringinfo += "</p>"
		dexstringinfo += "<table class=\"dir\" border=\"0\" style=\"line-height:100%;word-break:break-all;margin: 0 auto;\">"
		dexstringinfo += "<tbody><tr><th class=\"hd\">Method Name</th></tr>"

		for dexstr in method:
			dexstringinfo += "<tr><td>" + dexstr + "</td></tr>"
			
		dexstringinfo += "</tbody></table><br><br>"
		self.f.write(dexstringinfo)

	def stringinfo(self, string):
		stringdata = "<p style=\"text-align:center;line-height:100%;\">" 
		stringdata += "<span style=\"font-size:15.0pt;line-height:100%\">6. String Extraction</span>" 
		stringdata += "</p>"
		stringdata += "<table class=\"dir\" border=\"0\" style=\"line-height:100%;word-break:break-all;margin: 0 auto;\">"
		stringdata += "<tbody>"

		for xmlstr in string:
			stringdata += "<tr><td>" + xmlstr + "</td></tr>"

		stringdata += "</tbody></table><br><br>"
			
		self.f.write(stringdata)

	def nativeFileinfo(self, sofiledata):
		nativeinfo = "<p style=\"text-align:center;line-height:100%;\"><span style=\"font-size:15.0pt;line-height:100%\">7. Native File Information</span></p>"
		nativeinfo += "<p style=\"text-align:center;line-height:100%;\">"
		nativeinfo +="<span style=\"font-size:13.0pt;line-height:100%\">- Basic Information -</span>"
		nativeinfo +="</p>"
		nativeinfo +="<table class=\"dir\" border=\"0\" style=\"line-height:100%;word-break:break-all;margin: 0 auto;\"><tbody><tr><th class=\"hd\">SO Filename</th><th class=\"hd\">SHA1 Hash</th></tr>"
		for sofile in sofiledata:
			nativeinfo += "<tr><td>" + sofile[0] + "</td><td>" + sofile[1] + "</td></tr>"
		nativeinfo += "</tbody></table><br>"
		self.f.write(nativeinfo)

	def nativeStringinfo(self, sostring):
		sostringinfo = "<p style=\"text-align:center;line-height:100%;\">"
		sostringinfo +=	"<span style=\"font-size:13.0pt;line-height:100%\">- Suspicious String (IP, URL, Email) -</span>"
		sostringinfo += "</p>"
		sostringinfo += "<table class=\"dir\" border=\"0\" style=\"line-height:100%;word-break:break-all;margin: 0 auto;\">"
		sostringinfo += "<tbody>"

		for sostr in sostring:
			sostringinfo += "<tr><td>" + sostr + "</td></tr>"
			
		sostringinfo += "</tbody></table><br><br>"
		self.f.write(sostringinfo)

	def datasectioninfo(self, beforedatalog, afterdatalog):
		sectioninfo = "<p style=\"text-align:center;line-height:100%;\"><span style=\"font-size:15.0pt;line-height:100%\">8. Dynamic Analysis Information</span></p>" 
		sectioninfo += "<p style=\"text-align:center;line-height:100%;\">" 
		sectioninfo += "<span style=\"font-size:13.0pt;line-height:100%\">- Data Section Read&Write Status -</span>" 
		sectioninfo += "</p>"
		sectioninfo += "<table class=\"dir\" border=\"0\" style=\"line-height:100%;word-break:break-all;margin: 0 auto;\"><tbody><tr><th class=\"hd\">Initial Datasection</th></tr>"
		for datalog in beforedatalog:
			sectioninfo += "<tr><td>" + datalog + "</td></tr>"

		sectioninfo += "<tr><th class=\"hd\">Changed Datasection</th></tr>"
		for afterdatalog in afterdatalog:
			sectioninfo += "<tr><td>" + afterdatalog + "</td></tr>"

		sectioninfo += "</tbody></table><br>"
		self.f.write(sectioninfo)

	def logcatinfo(self, logcat):
		loginfo = "<p style=\"text-align:center;line-height:100%;\">"
		loginfo += "<span style=\"font-size:13.0pt;line-height:100%\">- Android Logcat -</span>"
		loginfo += "</p>" 
		loginfo += "<table class=\"dir\" border=\"0\" style=\"line-height:100%;word-break:break-all;margin: 0 auto;\">"
		loginfo += "<tbody>"

		for logstr in logcat:
			loginfo += "<tr><td>" + logstr + "</td></tr>"
			
		loginfo += "</tbody></table><br><br>"
		self.f.write(loginfo)

	def packetinfo(self, packetlist, iplist):
		packetinfo = "<p style=\"text-align:center;line-height:100%;\">"
		packetinfo += "<span style=\"font-size:13.0pt;line-height:100%\">- Packet Information -</span>"
		packetinfo += "</p>"
		packetinfo += "<table class=\"dir\" border=\"0\" style=\"line-height:100%;word-break:break-all;margin: 0 auto;\"><tbody><tr><th class=\"hd\">Time</th><th class=\"hd\">Source Address</th><th class=\"hd\">Destination Address</th></tr>"
		for packet in packetlist:
			packetinfo += "<tr><td>" + packet[0] + "</td><td>" + packet[1] + "</td><td>" + packet[2] + "</td></tr>"

		packetinfo += "</tbody></table><br>"
		packetinfo += "<p style=\"text-align:center;line-height:100%;\">"
		packetinfo += "<span style=\"font-size:13.0pt;line-height:100%\">- IP statistics -</span>"
		packetinfo += "</p>"
		packetinfo += "<table class=\"dir\" border=\"0\" style=\"line-height:100%;word-break:break-all;margin: 0 auto;\"><tbody>"
		for ip in iplist:
			packetinfo += "<tr><td>" + ip + "</td></tr>"
		packetinfo += "</tbody></table><br><br>"

		self.f.write(packetinfo)

	def endbody(self):
		endinfo = "</div><div class=\"border\">This application has been analyzed by androtool - developer Kim Namjun(@bunseokbot)<br><br></body></html>"
		self.f.write(endinfo)

	def __del__(self):
		pass