#!/usr/bin/python
import sys
import re
import os
import socket

class MailChecker(object):

	def _syntaxe_checker(self,mail_adr):
		pattern = "(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|\"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\\\[\x01-\x09\x0b\x0c\x0e-\x7f])*\")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\\])\""
		pattern2 = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
		result = re.match(pattern2,mail_adr)
		return (result != None)

	def _mx_checker(self,mail_adr,dns_server='8.8.8.8'):
		fqdn = mail_adr[mail_adr.rfind("@")+1:]
		cmd = 'dig {} mx {}'.format('' if dns_server == None else '@'+dns_server,fqdn)
		process = os.popen(cmd)
		result = str(process.read())
		mx_servers = []
		#print result
		if result.find("ANSWER SECTION:")!=-1:
			result = result[result.find("ANSWER SECTION:")+15:]
			result = result[:result.find(";;")].strip()
			mx_servers = [line[line.rfind(' ')+1:] for line in result.splitlines()]
		return mx_servers

	def _smtp_checker(self,smtp_server,mail_adr,smtp_port=25):
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		try:
			s.connect((smtp_server, int(smtp_port)))
			data = s.recv(4096)
			print(repr(data))
			print("EHLO localhost")
			s.send("EHLO localhost\r\n")
			data = s.recv(4096)
			print(data)
			print("MAIL FROM:<>")
			s.send("MAIL FROM:<>\r\n")
			data = s.recv(4096)
			print(data)
			print("RCPT TO:<{}>".format(mail_adr))
			s.send("RCPT TO:<{}>\r\n".format(mail_adr))
			data = s.recv(4096)
			print(data)
			if(int(data[:3])==250): is_valid =  True
			else: is_valid = False
			print("RSET")
			s.send("RSET\r\n")
			data = s.recv(4096)
			print(data)
			print("QUIT")
			s.send("QUIT\r\n")
			data = s.recv(4096)
			print(data)
			s.close()
			return is_valid
		except socket.error,msg:
			print("Exception {}".format(msg))

	def check_mail(self,mail_adr,dns_server="8.8.8.8"):
		if not self._syntaxe_checker(mail_adr):
			print("Syntaxe check failed")
			return
		print("Syntaxe check OK")
		mx_servers = self._mx_checker(mail_adr,dns_server)
		if mx_servers == []:
			print("MX server check failed")
			return
		print("MX Server check OK")
		print("Connecting to {}..".format(mx_servers[0]))
		if self._smtp_checker(mx_servers[0],mail_adr) == False:
			print("Mail server rejected the address : email address is not valid")
			return 
		print("Mail server did not reject the address : email address may be valid")
		
def main():
	if len(sys.argv)<2:
		print("Usage : python mailcheker.py mail_address")
		return
	mailchecker = MailChecker()
	mailchecker.check_mail(str(sys.argv[1]))

if __name__ == '__main__':
	main()