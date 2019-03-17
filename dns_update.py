#!/usr/bin/python3
import sys
from subprocess import call
from pylibopi import *
import getopt


CERTHANDLER		= "/usr/share/kinguard-certhandler/letsencrypt.sh"



### -------------- MAIN ---------------
if __name__=='__main__':

	standalone = False
	
	try:
		opts, args = getopt.getopt(sys.argv[1:],"ha")
	except getopt.GetoptError:
		print('Syntax: dns_update.py [-a]')
		sys.exit(2)

	for opt, arg in opts:
		print("OPTION is: '%s'" % opt)
		if opt == '-h':
			print("\t -a:\tRun Kinguard Certhandler in 'stand-alone' mode")
			sys.exit()
		elif opt in ("-a"):
			standalone=True

	try:
		provider = GetKeyAsString("dns","provider")
	except ValueError as e:
		print("No provider specified")
		sys.exit(1)

	try:
		enabled = GetKeyAsBool("dns","enabled")
	except ValueError as e:
		print("Missing dnsenabled parameter in sysconfig")
		sys.exit(1)


	if ( ( not enabled ) or ( provider != "OpenProducts" )) :
		print("OpenProducts dyndns service not enabled")
		sys.exit(0)

	try:
		success = UpdateDns()
		if ( not success ):
			print("Failed to update DNS, exit.")
			sys.exit(1)

		try:
			certargs=""
			# generate a letsencrypt certificate using the serial number
                        # check if we have a hostname+domain, if not use serial number
			try:
				GetKeyAsString("hostinfo","domain")
				GetKeyAsString("hostinfo","hostname")

			except:
				print("No hostinfo available trying serial")
				# no FQDN in sysconfig, try serial number
				try:
					serial=SerialNumber()
					print("-- TODO - use libopi to find default domain --")
					if "KEEP" in serial:
						# use mykeep.net domain
						fqdn = serial +".mykeep.net"
					else:
						# use op-i domain
						fqdn = serial + ".op-i.me"
					certargs = " -d " + fqdn
				except Exception as e:
					print("Failed to read serial number, exit")
					sys.exit(1)

			if standalone is True:
				certargs = certargs + " -ac"
				print("Running Certhandler in standalone mode")
			else:
				certargs = certargs + " -c"
			print("Updating signed certificates")
			#print(certargs)
			certstatus = call(CERTHANDLER + certargs, shell=True)
			if certstatus:
				print("Unable to create Let's Encrypt Certificate")
			else:
				print("Update successful.")					
		except Exception as e:
			print("Unable to create Let's Encrypt Certificate")
			print(e)

		sys.exit(0)

	except Exception as e:
		print(e)
		sys.exit(1)




