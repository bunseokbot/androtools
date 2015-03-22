import commands
import time
from datetime import datetime

class CERTParser:
	def __init__(self, certfile):
		self.certfile = certfile

	"""
	return starttime of CERTIFICATION FILE
	"""
	def starttime(self):
		out = commands.getoutput("openssl pkcs7 -inform DER -in " + self.certfile + " -print_certs | openssl x509 -noout -startdate")
		starttime = out.replace("notBefore=", "")
		split_time = starttime.split(' ')
		for date in split_time:
			if date == "":
				split_time.remove(date)
			month = split_time[0]
			if "Jan" in month:
				convert_month = "01"
			elif "Feb" in month:
				convert_month = "02"
			elif "Mar" in month:
				convert_month = "03"
			elif "Apr" in month:
				convert_month = "04"
			elif "May" in month:
				convert_month = "05"
			elif "Jun" in month:
				convert_month = "06"
			elif "Jul" in month:
				convert_month = "07"
			elif "Aug" in month:
				convert_month = "08"
			elif "Sep" in month:
				convert_month = "09"
			elif "Oct" in month:
				convert_month = "10"
			elif "Nov" in month:
				convert_month = "11"
			elif "Dec" in month:
				convert_month = "12"
			else:
				convert_month = "00"

		visual_date = split_time[3] + "-" + convert_month + "-" + split_time[1] + " " + split_time[2]
		return visual_date

	def fingerprint(self):
		certfile_fingerprint = "openssl pkcs7 -inform DER -in " + self.certfile + " -print_certs | openssl x509 -noout -fingerprint"
		fingerprint_cmd = commands.getoutput(certfile_fingerprint)
		return fingerprint_cmd.replace("SHA1 Fingerprint=", "")

	def issuer(self):
		issuer = ""
		certfile_issuer = "openssl pkcs7 -inform DER -in " + self.certfile + " -print_certs | openssl x509 -noout -issuer"
		issuer_cmd = commands.getoutput(certfile_issuer)
		split_info = issuer_cmd.split("/")
		for i in range(0, len(split_info)):
			if "CN=" in split_info[i]:
				issuer = split_info[i].replace("CN=", "")
			if 'L=' in split_info[i]:
				issuer = split_info[i].replace("L=", "")
			if 'OU=' in split_info[i]:
				issuer = split_info[i].replace("OU=", "")
			if 'O=' in split_info[i]:
				issuer = split_info[i].replace("O=", "")
			if 'C=' in split_info[i]:
				issuer = split_info[i].replace("C=", "")
		return issuer

	def __del__(self):
		pass
