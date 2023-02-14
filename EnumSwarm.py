#!/usr/bin/env python3

import random
import sys
import argparse
import requests
from lxml import html
import urllib3
import time
import nmap

# Create an instance of the nmap.PortScanner class
def check_port_syn_scan(target):
    nm = nmap.PortScanner()
    ports = [80, 443, 8080, 8443, 8000, 8888, 5000, 3000, 8060, 8070]
    nm.scan(hosts=target, arguments='-sS -p %s' % ','.join(str(p) for p in ports))
    positive_results = []
    for host in nm.all_hosts():
        for port in nm[host]['tcp']:
            if nm[host]['tcp'][port]['state'] == 'open':
                positive_results.append(target + ':' + str(port))
    return positive_results

# Nobody wants to see SSL warnings :-P
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def doSleep(timing):

	if timing == 0:
		time.sleep(random.randrange(90,120))
	elif timing == 1:
		time.sleep(random.randrange(60,90))
	elif timing == 2:
		time.sleep(random.randrange(30,60))
	elif timing == 3:
		time.sleep(random.randrange(10,20))
	elif timing == 4:
		time.sleep(random.randrange(5,10))

def save_list_to_file(file_path, list_to_save):
    with open(file_path, 'w') as f:
        for item in list_to_save:
            f.write("%s\n" % item)

def getHostnames(domain):

	url = 'https://crt.sh/?q={0}'.format(domain)
	headers = {'User-Agent': useragent,
		   'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
		   'Accept-Language': 'en-US,en;q=0.5',
		   'Accept-Encoding': 'gzip, deflate',
		   'Referer': 'https://crt.sh/'}

	try:

		r = requests.get(url,headers=headers,proxies=proxies,verify=False)
		if r.status_code == requests.codes.ok:
			tree = html.fromstring(r.text)
			crtsh_hostnames = [x.lower() for x in tree.xpath('//td[@class="outer"]/table/tr/td[5]/text()')]

			# Clean up the list for valid hostnames
			hostnames = []
			for hostname in crtsh_hostnames:
				if hostname not in hostnames and '*' not in hostname:
					hostnames.append(hostname)

			# Print hostnames
			for hostname in hostnames:
				print(hostname)

			return hostnames
		return None


	except Exception as e:
		print('[!] An exception occurred while querying crt.sh: {0}'.format(e))

if __name__ == "__main__":

	parser = argparse.ArgumentParser(
	description='Extracts hosts from certificate transparency logs at cert.sh',
	epilog = '''
Examples:
./{0} -d google.com
./{0} -f domains.txt'''.format(sys.argv[0]),
	formatter_class=argparse.RawDescriptionHelpFormatter)

	parser.add_argument('-d','--domain', help='Domain to query certificate transparency logs for', required=False, default=None, type=str, dest='domain')
	parser.add_argument('-f','--file', help='File containing domains to query certificate transparency logs for', required=False, default=None, type=str, dest='file')
	parser.add_argument('-t','--timing', help='Modifies request timing to avoid getting banned for being a bot. Slowest(0) = 90-120 seconds, Default(3) = 10-20 seconds, Fastest(5) = no delay', required=False, default=3, type=int, choices=range(0,6), dest='timing')
	parser.add_argument('-p', '--proxy', help='Proxy example: http://127.0.0.1:8080', required=False, default=None, type=str, dest='proxy')
	parser.add_argument('-u', '--useragent', help='User agent string to make requests with', required=False, default='Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)', type=str, dest='useragent')

	args = parser.parse_args()

	# Global Variables

	useragent = args.useragent
	if args.proxy:
		proxies = {'http': args.proxy, 'https': args.proxy}
	else:
		proxies = None
	
	if args.file:
		try:
			with open(args.file) as f:
				domains = [line.rstrip('\n') for line in f]
		except Exception as e:
			print('[!] Trouble opening file {0}\n\n{1}\n\n'.format(args.file,e))
			exit(1)
	elif args.domain:
		domains = [args.domain]
	else:
		print('[!] Either a domain (-d, --domain) or file containing domains (-f, --file) is required!')
		exit(1)

	# Main logic

	sub_domains=	getHostnames(domains[0])
	save_list_to_file("domain-list.txt",sub_domains)

	host_ports = []
	for sub_domain in sub_domains:
		result = check_port_syn_scan(sub_domain)
		if len(result)!=0:
			host_ports.append(result)
	save_list_to_file("host-ports.txt",host_ports)
	print(host_ports)
