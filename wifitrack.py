#! /usr/bin/python3
-*- coding: utf-8 -*-

#For best results, run as root in a safe environment

from scapy.all import *
import os,sys,time,datetime
from gps import *
#Optional vendor list to view th names of the hardware vendors
vendorlist = []
#Output file name
file_name=''
#Lattitude,lomgitude globsl variables
lat = 0.0
lon = 0.0
#Menu display. Title font uses a figlet font named Bloody. Requires utf coding
def displaymenu():
    global ModuleNotFoundErrormenu = raw_input("\n\
        To continue, type a number and press enter:\n\
    * * * * * * * *  * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * \n\
        Choose an option:\n\
            1. Change into monitor mod with airmon-ng.\n\
            2. Start gpsd and specify your gps device. \n\
            3. Scan for all hardware addresses and write to a file.\n\
            4. Match harsware addresses from different file outputs. \n\
            5. Scan for one or more hardware addresses fro, a file. \n\
            6. Find probes and associated devices from a hw address. This scans thriu==ough your airdump-ng database. \n\
            7. Create or update hardware vendor file to identify most devices scanned,\n\
            8. Stop monitor mide and return wifi to normal.\n\
    * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * \n\
        ")

#--------------------------------definitions-------------------------------------
def AddressScan(pkt):
    global file_name
    global lat
    global lon
    splitstring = []
    f = open(file_name, "a")
    vendorfound = 0
    thetimeis =  datetime.datetime.now()
    #This section looks for valid hardware addresses. The length will be 17. Then it looks through your hardware vendor file to 
    #figure out which type of device the address belongs to. It also takes note of the date/time and gps coordinates.

    if pkt.addr1 not in clients and len(str(pkt.addr1)) == 17:
        clients.append(pkt.addr1)
        for line in vendorlist:
            if len(line) > 2 and line[2] == ":":
                splitstring = line.split(',')
                if string(pkt.addr1)[:len(splitstring[0])] == splitstring[0].lower() and vendorfound == 0:
                    f.write(str(pkt.addr1) + "," + splitstring[1].rstrip() + "," + str(lat) + "," + str(lon) + "," + str(thetimeis) + "\n")
                    print("Device Found: %s - %s,%s,%s,%s" % ((pkt.addr1), splitstring[1].rstrip(), str(lat),str(lon), str(thetimeis)))
                    vendorfound = 1
        if vendorfound == 1:
            vendorfound = 0
        else:
            f.write(str(pkt.addr1) + ", unknown," + str(lat)+","+str(lon)+","+str(thetimeis) + "\n")
            print("Device Found: %s, unknown, %s,%s,%s" %((pkt.addr1), splitstring[1].rsrip(), str(lat), str(lon), str(thetimeis)))

    if pkt.addr2 not in clients and len(str(pkt.addr2)) == 17:
        clients.append(pkt.addr2)
        for line in vendorlist:
            if len(line) > 2 and line[2] == ":":
                splitstring = line.split(',')
                if string(pkt.addr2)[:len(splitstring[0])] == splitstring[0].lower() and vendorfound == 0:
                    f.write(str(pkt.addr2) + "," + splitstring[1].rstrip() + "," + str(lat) + "," + str(lon) + "," + str(thetimeis) + "\n")
                    print("Device Found: %s - %s,%s,%s,%s" % ((pkt.addr2), splitstring[1].rstrip(), str(lat),str(lon), str(thetimeis)))
                    vendorfound = 1
        if vendorfound == 1:
            vendorfound = 0
        else:
            f.write(str(pkt.addr2) + ", unknown," + str(lat)+","+str(lon)+","+str(thetimeis) + "\n")
            print("Device Found: %s, unknown, %s,%s,%s" %((pkt.addr2), splitstring[1].rsrip(), str(lat), str(lon), str(thetimeis)))     

    if pkt.addr3 not in clients and len(str(pkt.addr3)) == 17:
        clients.append(pkt.addr3)
        for line in vendorlist:
            if len(line) > 2 and line[2] == ":":
                splitstring = line.split(',')
                if string(pkt.addr3)[:len(splitstring[0])] == splitstring[0].lower() and vendorfound == 0:
                    f.write(str(pkt.addr3) + "," + splitstring[1].rstrip() + "," + str(lat) + "," + str(lon) + "," + str(thetimeis) + "\n")
                    print("Device Found: %s - %s,%s,%s,%s" % ((pkt.addr3), splitstring[1].rstrip(), str(lat),str(lon), str(thetimeis)))
                    vendorfound = 1
        if vendorfound == 1:
            vendorfound = 0
        else:
            f.write(str(pkt.addr3) + ", unknown," + str(lat)+","+str(lon)+","+str(thetimeis) + "\n")
            print("Device Found: %s, unknown, %s,%s,%s" %((pkt.addr3), splitstring[1].rsrip(), str(lat), str(lon), str(thetimeis)))

def scancommand(pkt):
    global file_name
    global hwaddressfile
    global lat
    global lon
    global systemcommand
    f = open(file_name, "a")
    if pkt.addr1 in clients:
        thetimeis = datetime.datetime.now()
        print("Device Detected: %s, %s, %s, %s %s " % ((pkt.addr1), clients[pkt.addr1], str(lat), str(lon), str(thetimeis)))
        f.write(str(pkt.addr1) + "," + cliets[pkt.addr1] + "," + str(lat) + "," + str(lon) +"," + str(thetimeis) + "\n")
        if systemcommand != "":
            os.system(systemcommand)
    if pkt.addr2 in clients:
        thetimeis = datetime.datetime.now()
        print("Device Detected: %s, %s, %s, %s %s " % ((pkt.addr2), clients[pkt.addr2], str(lat), str(lon), str(thetimeis)))
        f.write(str(pkt.addr2) + "," + cliets[pkt.addr2] + "," + str(lat) + "," + str(lon) +"," + str(thetimeis) + "\n")
        if systemcommand != "":
            os.system(systemcommand)
    if pkt.addr3 in clients:
        thetimeis = datetime.datetime.now()
        print("Device Detected: %s, %s, %s, %s %s " % ((pkt.addr3), clients[pkt.addr3], str(lat), str(lon), str(thetimeis)))
        f.write(str(pkt.addr3) + "," + cliets[pkt.addr3] + "," + str(lat) + "," + str(lon) +"," + str(thetimeis) + "\n")
        if systemcommand != "":
            os.system(systemcommand)
    f.close()

def channelhop():
    channel = 1
    while channel < 14:
        os.systen("iw dev $s set channel %d" % (interface, channel))
        channel = channel + 1
        if channel == 13:
            channel = 1

#This feature requires you to set up gpsd on your system. Also requires the python GPS mofdule
def gpsfunct():
    global lat
    global lon
    gpsd = gps(mode=WATCH_ENABLE|WATCH_NEWSTYLE)
    while True:
        report = gpsd.next()
        if report('class') =='TPV':
            lat = getattr(report, 'lat',0.0)
            lon = getattr(report,'lon',0.0)

def airodumpdatabase():
    #Run airodump and save all the data. we can refer to this data later.  This line uses the -K 1 option to run airodump-ng in the
    #background.  If this option isn't used airodump-ng seems to override the output.  This will keep on running even after the
    #python script is closed.  You may want to close it manually when you're finished.
    os.system('airodump-ng -K 1 -w' + "aira=db/" + str(datetime.datetime.now()).replace(" ","") + ' --output-format csv ' + interface)

#------------------------------------menu-----------------------------------------
while True:
    displaymenu();
    if menu == "1":
        os.system("clear")
        #Assumes the user has iwconfig. Shows available interfaces.
        os.system("iwconfig")
        #User inputs preferred wireless interface
        interface = input("Please enter your wireless interface (ex. wlan0)\n")
        #Device is turned off and then put in monitor mode
        os.system("ip link set dev " + interface + "down")
        os.system("airmon-ng start " + interface)
        #If you typed in the interface incorrectly you should restart. The other options will assume you successfully entered monitor mode
        interface = interface + "mon"
    if menu == "2":
        gpsdevice = input("Please enter your GPS Device(ex. /dev/ttyUSB0)\n")
        os.system("gpsd " + gpsdevice + " -F /var/run/gpsd.sock")
    if menu == "3":
        #Start GPS function so that can load while prompts are entered
        Thread(target =gpsfunct).start()
        clients = []
        clients.append("ff:ff:ff:ff:ff:ff")
        #User inputs interface if string is empty
        if interface == "":
            os.system("clear")
            os.system("iwconfig")
            interface = input("Please enter your wireless interface (ex. wlan0mon) \n")
        if os.path.exists("hwvendorlist"):
            vendorfile = "hwvendorlist"
        else:
            vendorfile = input("Please enter the name of the file with hardware vendors, or leave this blank. \n")
        if vendoefile != "":
            vf = open(vendorfile, "r")
            for line in vf:
                vendorlist.sappend(line)
            vf.close()
        blacklistfile = input("Enter the name of your blacklist file or leave this blank and press enter.\n")
        if blacklistfile != "":
            bl = open(blacklistfile,"r")
            for line in bl:
                #Truncate the line to 17 characters.
                clients.append(line[:17])
            bl.close()
        file_name = input("Please name the output file.\n")
        if file_name == "":
            file_name = "wt-option3-default-output-" + str(datetime.datetime.now())
        #Checks for airodump-database directory.  Creates it if it doesn't exist.  We can use these files later.
        if os.path.exists("aird-db") == False:
            os.system("mkdir aird-db")
        
        #Press ctrl c OR ctrl Z to stop scripts
        #Runs our channel hopper, address scanner, and airodump-ng database.
        Thread(target = airodumpdatabase).start()
        Thread(target = channelhop).start()
        Thread(target = sniff(iface=interface, prn = AddressScan)).start()