#!/usr/bin/python3
import urllib.parse
import json
from base64 import b64encode
import hashlib
from OpenSSL import crypto
import configparser
import sys

AUTH_SERVER		= "auth.openproducts.com"
AUTH_PATH		= "/"
AUTH_FILE		= "auth.php"
DNS_FILE		= "update_dns.php"

SYSINFO			= "/etc/opi/sysinfo.conf"
ACCESSINFO		= "/etc/opi/opi-access.conf"

#TODO: more errorchecking

# Constants used on serverside
FAIL		= 0
SUCCESS		= 1
WAIT		= 2
REQUEST_KEY	= 3

def sendsignedchallenge(conn, unit_id, fp_pkey, challenge):
	fh_pkey = open(fp_pkey,'r')
	pkey_data=fh_pkey.read()
	fh_pkey.close()
	pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, pkey_data )

	signature = crypto.sign(pkey, str.encode( challenge ), "sha1")

	data = {}
	data["unit_id"] = unit_id
	data["dns_signature"] = bytes.decode( b64encode( signature ) )

	post = {}
	post["data"] = json.dumps( data )

	params = urllib.parse.urlencode( post, doseq=True )
	headers = {"Content-type": "application/x-www-form-urlencoded"}

	path = urllib.parse.quote(AUTH_PATH + AUTH_FILE)

	conn.request("POST", path, params, headers)

	r = conn.getresponse()
	data = r.read()

	if r.status not in ( 200, 403):
		print("Wrong status %d"%r.status)
		return False

	rp = json.loads( data.decode('utf-8') )

	token = ""

	if r.status == 200:
		if "token" not in rp:
			print("Unexpected server response, no token %s" % rp)
			return False
		else:
			token = rp["token"]

	if r.status == 403:
		print("Failed to get token")
		return False

	return token

def sendDNSupdate(conn, unit_id,token):
	data = {}
	data["unit_id"] = unit_id

	params = urllib.parse.urlencode( data, doseq=True )
	headers = {"Content-type": "application/x-www-form-urlencoded","token":token}
	path = urllib.parse.quote(AUTH_PATH + DNS_FILE)

	conn.request("POST", path, params, headers)

	r = conn.getresponse()
	data = r.read()

	if r.status not in ( 200, 403):
		print("Wrong status %d"%r.status)
		return False

	rp = json.loads( data.decode('utf-8') )

	if r.status == 200:
		print("Got '200 OK'")
		return True
	if r.status == 403:
		print("Failed to update")
		return False


def getchallenge(conn, unit_id):

	qs = urllib.parse.urlencode({'unit_id':unit_id}, doseq=True)
	path = urllib.parse.quote(AUTH_PATH + AUTH_FILE) + "?"+qs

	conn.request( "GET", path)

	r = conn.getresponse()
	data = r.read()

	if r.status != 200:
		print("Unable to parse server response")
		return False

	rp = json.loads( data.decode('utf-8') )

	if "challange" not in rp:
		print("Unable to parse server response, no challange %s", rp)
		return False

	return rp["challange"]


def authenticate( conn, unit_id, fp_pkey ):

	challenge = getchallenge( conn, unit_id )

	if not challenge:
		print("Failed to get challenge")
		return (500, None)

	token = sendsignedchallenge(conn, unit_id, fp_pkey, challenge)

	if not token:
		print("Failed to get token")
		return (500, None)

	return (200, token)

def add_section_header(properties_file, header_name):
	# configparser.ConfigParser requires at least one section header in a properties file.
	# Our properties file doesn't have one, so add a header to it on the fly.
	yield '[{}]\n'.format(header_name)
	for line in properties_file:
		yield line



### -------------- MAIN ---------------
if __name__=='__main__':

	try:
		fh_sysconf = open(SYSINFO, encoding="utf_8")
	except Exception as e:
		print("Error opening SYSINFO file: "+SYSINFO)
		print(e)
		sys.exit(1)

	sysconf = configparser.ConfigParser()
	# There are no sections in our ini files, so add one on the fly.
	try:
		sysconf.read_file(add_section_header(fh_sysconf, 'sysinfo'), source=SYSINFO)
		if 'sysinfo' not in sysconf:
			print("Missing parameters in sysinfo")
			sys.exit(1)
		sysinfo = sysconf['sysinfo']
		if 'unit_id' not in sysinfo:
			print("Missing parameters in sysinfo")
			sys.exit(1)
		unit_id = sysinfo['unit_id'].strip('"')
		if 'capath' not in sysinfo:
			print("Missing parameters in sysinfo")
			sys.exit(1)
		cafile = sysinfo['capath'].strip('"')

	except Exception as e:
		print("Error parsing sysconfig")
		print(e)
		sys.exit(1)


	try:
		fh_accessconf = open(ACCESSINFO, encoding="utf_8")
	except Exception as e:
		print("Error opening ACCESSINFO file: "+ACCESSINFO)
		print(e)
		sys.exit(1)

	accessconf = configparser.ConfigParser()
	# There are no sections in our ini files, so add one on the fly.
	try:
		accessconf.read_file(add_section_header(fh_accessconf, 'accessinfo'), source=ACCESSINFO)
		if 'accessinfo' not in accessconf:
			print("Missing parameters in accessinfo")
			sys.exit(1)
		accessinfo = accessconf['accessinfo']
		if 'dns-key' not in accessinfo:
			print("Missing parameters in accessinfo")
			sys.exit(1)
		fp_pkey = accessinfo['dns-key'].strip('"')
		if 'dyndns' not in accessinfo:
			print("Missing dyndns parameters in accessinfo")
			sys.exit(1)
		if accessinfo['dyndns'].strip('"') != "yes":
			print("DynDNS service not enabled.")
			sys.exit(0)
	except Exception as e:
		print("Error parsing access config")
		print(e)
		sys.exit(1)


	#print(unit_id)

	try:
		import ssl
		import http.client

		ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)

		ctx.options |= ssl.OP_NO_SSLv2
		ctx.verify_mode = ssl.CERT_REQUIRED

		try:
			ctx.load_verify_locations( cafile )
		except Exception as e:
			print("CA file error")
			print(e)
			sys.exit(1)

		conn = http.client.HTTPSConnection(AUTH_SERVER, 443, context=ctx)

		response = authenticate(conn, unit_id, fp_pkey)
	except http.client.HTTPException as e:
		print(e)
	token = response[1]
	sendDNSupdate(conn,unit_id,token)



