#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import argparse
import socket
import os
import sys
import struct
import time
import random
import traceback # useful for exception handling
import threading

def setupArgumentParser() -> argparse.Namespace:
     
        parser = argparse.ArgumentParser(
            description='A collection of Network Applications developed for SCC.203.')
        parser.set_defaults(func=ICMPPing, hostname='lancaster.ac.uk')
        subparsers = parser.add_subparsers(help='sub-command help')
        
        parser_p = subparsers.add_parser('ping', aliases=['p'], help='run ping')
        parser_p.set_defaults(timeout=4)
        parser_p.add_argument('hostname', type=str, help='host to ping towards')
        parser_p.add_argument('--count', '-c', nargs='?', type=int,
                              help='number of times to ping the host before stopping')
        parser_p.add_argument('--timeout', '-t', nargs='?',
                              type=int,
                              help='maximum timeout before considering request lost')
        parser_p.set_defaults(func=ICMPPing)

        parser_t = subparsers.add_parser('traceroute', aliases=['t'],
                                         help='run traceroute')
        parser_t.set_defaults(timeout=4, protocol='icmp')
        parser_t.add_argument('hostname', type=str, help='host to traceroute towards')
        parser_t.add_argument('--timeout', '-t', nargs='?', type=int,
                              help='maximum timeout before considering request lost')
        parser_t.add_argument('--protocol', '-p', nargs='?', type=str,
                              help='protocol to send request with (UDP/ICMP)')
        parser_t.set_defaults(func=Traceroute)
        
        parser_pt = subparsers.add_parser('paris-traceroute', aliases=['pt'],
                                         help='run paris-traceroute')
        parser_pt.set_defaults(timeout=4, protocol='icmp')
        parser_pt.add_argument('hostname', type=str, help='host to traceroute towards')
        parser_pt.add_argument('--timeout', '-t', nargs='?', type=int,
                              help='maximum timeout before considering request lost')
        parser_pt.add_argument('--protocol', '-p', nargs='?', type=str,
                              help='protocol to send request with (UDP/ICMP)')
        parser_pt.set_defaults(func=ParisTraceroute)

        parser_w = subparsers.add_parser('web', aliases=['w'], help='run web server')
        parser_w.set_defaults(port=8080)
        parser_w.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_w.set_defaults(func=WebServer)

        parser_x = subparsers.add_parser('proxy', aliases=['x'], help='run proxy')
        parser_x.set_defaults(port=8000)
        parser_x.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_x.set_defaults(func=Proxy)

        args = parser.parse_args()
        return args


class NetworkApplication:

    def checksum(self, dataToChecksum: str) -> str:
        csum = 0
        countTo = (len(dataToChecksum) // 2) * 2
        count = 0

        while count < countTo:
            thisVal = dataToChecksum[count+1] * 256 + dataToChecksum[count]
            csum = csum + thisVal
            csum = csum & 0xffffffff
            count = count + 2

        if countTo < len(dataToChecksum):
            csum = csum + dataToChecksum[len(dataToChecksum) - 1]
            csum = csum & 0xffffffff

        csum = (csum >> 16) + (csum & 0xffff)
        csum = csum + (csum >> 16)
        answer = ~csum
        answer = answer & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)

        answer = socket.htons(answer)

        return answer

    def printOneResult(self, destinationAddress: str, packetLength: int, time: float, ttl: int, destinationHostname=''):
        if destinationHostname:
            print("%d bytes from %s (%s): ttl=%d time=%.2f ms" % (packetLength, destinationHostname, destinationAddress, ttl, time))
        else:
            print("%d bytes from %s: ttl=%d time=%.2f ms" % (packetLength, destinationAddress, ttl, time))

    def printAdditionalDetails(self, packetLoss=0.0, minimumDelay=0.0, averageDelay=0.0, maximumDelay=0.0):
        print("%.2f%% packet loss" % (packetLoss))
        if minimumDelay > 0 and averageDelay > 0 and maximumDelay > 0:
            print("rtt min/avg/max = %.2f/%.2f/%.2f ms" % (minimumDelay, averageDelay, maximumDelay))

    def printMultipleResults(self, ttl: int, destinationAddress: str, measurements: list, destinationHostname=''):
        latencies = ''
        noResponse = True
        for rtt in measurements:
            if rtt is not None:
                latencies += str(round(rtt, 3))
                latencies += ' ms  '
                noResponse = False
            else:
                latencies += '* ' 

        if noResponse is False:
            print("%d %s (%s) %s" % (ttl, destinationHostname, destinationAddress, latencies))
        else:
            print("%d %s" % (ttl, latencies))

class ICMPPing(NetworkApplication):

    def receiveOnePing(self, icmpSocket, destinationAddress, ID, timeout):

        # 1. Wait for the socket to receive a reply
        self.recieved = icmpSocket.recv(28)
        # 2. Once received, record time of receipt, otherwise, handle a timeout
        recivedTime = time.time()
        # 3. Compare the time of receipt to time of sending, producing the total network delay
        self.totalNetworkDelay = (recivedTime - self.sendTime)*1000
        # 4. Unpack the packet header for useful information, including the ID
        self.unpacked = struct.unpack("bbHHh",self.ICMPHeader)
        # 5. Check that the ID matches between the request and reply
        if(self.identifier == self.unpacked[4]):
            pass
        else:
            print("failed")

        # 6. Return total network delay
        

    def sendOnePing(self, icmpSocket, destinationAddress, ID):
        # 1. Build ICMP header
        CheckSumHeader = struct.pack("bbHHh",8,0,0, self.identifier,self.checkSumSequenceNum)

        # 2. Checksum ICMP packet using given function
        checkSumValue = self.checksum(CheckSumHeader)
        # 3. Insert checksum into packet
        self.ICMPHeader = struct.pack("bbHHh",8,0,checkSumValue,self.identifier,self.sequenceNum)
        # 4. Send packet using socket
        icmpSocket.sendto(self.ICMPHeader,(destinationAddress,1024))
        # 5. Record time of sending
        self.sendTime = time.time()
        pass

    def doOnePing(self, destinationAddress, timeout):
        # 1. Create ICMP socket
        ICMPPscoket = socket.socket(socket.AF_INET,socket.SOCK_RAW, socket.IPPROTO_ICMP)
        ICMPPscoket.connect((destinationAddress,1024))
        # 2. Call sendOnePing function
        self.sendOnePing(ICMPPscoket,destinationAddress,self.sequenceNum)
        # 3. Call receiveOnePing function
        self.receiveOnePing(ICMPPscoket,destinationAddress,self.sequenceNum,0)
        # 4. Close ICMP socket
        ICMPPscoket.close
        # 5. Return total network delay
        pass

    def __init__(self, args):
        self.identifier =1
        self.checkSumSequenceNum = 1
        self.sequenceNum = 1
        self.sendTime = 0
        self.totalNetworkDelay = 1
        print('Ping to: %s...' % (args.hostname))
        hostIP = socket.gethostbyname(args.hostname)# 1. Look up hostname, resolving it to an IP address
        # 2. Call doOnePing function, approximately every second
        while True:
            self.doOnePing(hostIP,1)
            self.identifier+=1
            self.sequenceNum+=1
            self.printOneResult(hostIP,sys.getsizeof(self.recieved),self.totalNetworkDelay,5, args.hostname)
            time.sleep(1)


class Traceroute(NetworkApplication):

    def receiveOnePing(self, traceRouteSocket, destinationAddress, ID, timeout):
        self.recieved = traceRouteSocket.recvfrom(28)

        self.hopIp = self.recieved[1][0]

        try:
            self.hopName = socket.gethostbyaddr(self.hopIp)
        except socket.herror:
            self.hopName = ("null")

        recivedTime = time.time()
        self.totalNetworkDelay = (recivedTime - self.sendTime)*1000
        self.unpacked = struct.unpack("bbHHh",self.ICMPHeader)
        if(destinationAddress == self.recieved[1][0]):
            print("destination achieved")
            sys.exit()
        else:
            pass
       

        


    def sendOnePing(self, traceRouteSocket, destinationAddress, ID):
        CheckSumHeader = struct.pack("bbHHh",8,0,0, self.identifier,self.checkSumSequenceNum)
        checkSumValue = self.checksum(CheckSumHeader)
        self.ICMPHeader = struct.pack("bbHHh",8,0,checkSumValue,self.identifier,self.sequenceNum)
        traceRouteSocket.sendto(self.ICMPHeader,(destinationAddress,1024))
        self.sendTime = time.time()
        pass

    def doOnePing(self,traceRouteSocket ,destinationAddress, timeout):
        self.sendOnePing(traceRouteSocket,destinationAddress,self.sequenceNum)
        self.receiveOnePing(traceRouteSocket,destinationAddress,self.sequenceNum,0)
        pass


    def __init__(self, args):
        self.ttl=1
        traceRoute = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)
        traceRoute.setsockopt(socket.SOL_IP,socket.IP_TTL,self.ttl)
        hostIP = socket.gethostbyname(args.hostname)
        self.checkSumSequenceNum = 1
        self.sequenceNum = 1
        self.identifier = 0
        while True:
            self.doOnePing(traceRoute,hostIP,1)
            traceRoute.close
            traceRoute.setsockopt(socket.SOL_IP,socket.IP_TTL,self.ttl)
            # Please ensure you print each result using the printOneResult method!
            print('Traceroute to: %s...' % (args.hostname))
            self.printOneResult(self.recieved[1][0],sys.getsizeof(self.recieved),self.totalNetworkDelay,self.ttl, self.hopName[0])
            self.ttl += 1
            time.sleep(1)

class ParisTraceroute(NetworkApplication):

    def receiveOnePing(self, traceRouteSocket, destinationAddress, ID, timeout):

        try:
            self.recieved = traceRouteSocket.recvfrom(28)
        except socket.timeout:
            print("cant access node")

        self.hopIp = self.recieved[1][0]

        try:
            self.hopName = socket.gethostbyaddr(self.hopIp)
        except socket.herror:
            self.hopName = ("null")

        recivedTime = time.time()
        self.totalNetworkDelay = (recivedTime - self.sendTime)*1000
        self.unpacked = struct.unpack("bbHHh",self.ICMPHeader)
        if(destinationAddress == self.recieved[1][0]):
            print("destination achieved")
            sys.exit()
        else:
            pass
        

        
    def sendOnePing(self, traceRouteSocket, destinationAddress, ID):
        CheckSumHeader = struct.pack("bbHHh",8,0,0, self.identifier,self.checkSumSequenceNum)
        checkSumValue = self.checksum(CheckSumHeader)
        self.ICMPHeader = struct.pack("bbHHh",8,0,checkSumValue,self.identifier,self.sequenceNum)
        traceRouteSocket.sendto(self.ICMPHeader,(destinationAddress,1024))
        self.sendTime = time.time()
        pass

    def doOnePing(self,traceRouteSocket ,destinationAddress, timeout):
        self.sendOnePing(traceRouteSocket,destinationAddress,self.sequenceNum)
        self.receiveOnePing(traceRouteSocket,destinationAddress,self.sequenceNum,0)
        pass


    def __init__(self, args):
        self.ttl=1
        traceRoute = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)
        traceRoute.settimeout(args.timeout)
        traceRoute.setsockopt(socket.SOL_IP,socket.IP_TTL,self.ttl)
        hostIP = socket.gethostbyname(args.hostname)
        self.checkSumSequenceNum = 1
        self.sequenceNum = 1
        self.identifier = 1
        while True:
            self.doOnePing(traceRoute,hostIP,1)
            traceRoute.close
            traceRoute.setsockopt(socket.SOL_IP,socket.IP_TTL,self.ttl)
            # Please ensure you print each result using the printOneResult method!
            print('Paris-Traceroute to: %s...' % (args.hostname))
            self.printOneResult(self.recieved[1][0],sys.getsizeof(self.recieved),self.totalNetworkDelay,self.ttl, self.hopName[0])
            #self.printAdditionalDetails()
            self.ttl += 1
            time.sleep(1)

class WebServer(NetworkApplication):

    def handleRequest(self,tcpSocket):
        # 1. Receive request message from the client on connection socket
        data = tcpSocket.recv(28)
        # 2. Extract the path of the requested object from the message (second part of the HTTP header)
        dataDecode = data.decode()
        dataDecode = dataDecode.splitlines()
        splitData = dataDecode[0].split()
        print(splitData[1])
        # 3. Read the corresponding file from disk
        filePath = splitData[1].replace("/","")
        try:
            file = open(filePath,"r")
        except:
            print("404")
        print(file.read())

        HTTPHeader = "HTTP/1.1 200 OK \r\n\r\n"

        readFile = file.read()
        readFile = HTTPHeader + readFile

        tcpSocket.sendall(readFile.encode())
        tcpSocket.close()


        # 4. Store in temporary buffer
        # 5. Send the correct HTTP response error
        # 6. Send the content of the file to the socket
        # 7. Close the connection socket
        pass

    def __init__(self, args):
        print('Web Server starting on port: %i...' % (args.port))
        # 1. Create server socket
        webServer = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        webServer.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        self.address = ("",args.port)

        # 2. Bind the server socket to server address and server port
        webServer.bind(self.address)

        # 3. Continuously listen for connections to server socket
        webServer.listen(1)

        # 4. When a connection is accepted, call handleRequest function, passing new connection socket (see https://docs.python.org/3/library/socket.html#socket.socket.accept)
        self.recived,self.newAdress = webServer.accept()

        self.handleRequest(self.recived)
        # 5. Close server socket
        webServer.close()

class Proxy(NetworkApplication):
    
    def proxyHandler(self,connSocket,clientAddress):
        request = connSocket.recv(8000)
        request = request.decode()
        print(request)
        firstLine = request.split('\n')[0]
        url = firstLine.split()
        #http = firstLine.find("://")
        #print(http)
        print(url[1])
        http = url[1].replace("http://","")
        http = http.replace("/","")
        serverInfo = (http,80)
        print (http)
        encodeRequest = request.encode()
        if url[0] == 'GET':
            getSocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            getSocket.connect(serverInfo)
            getSocket.send(encodeRequest)
            serverRecived = getSocket.recv(8000)
        else:
            print("not a get request")
        
        getSocket.close()
        connSocket.sendall(serverRecived)
        connSocket.close()
        pass

    def handleRequest(self,tcpSocket):
        data = tcpSocket.recv(28)

        dataDecode = data.decode()
        dataDecode = dataDecode.splitlines()
        splitData = dataDecode[0].split()

        filePath = splitData[1].replace("/","")
        try:
            file = open(filePath,"r")
        except:
            print("404")

        HTTPHeader = "HTTP/1.1 200 OK \r\n\r\n"

        readFile = file.read()
        readFile = HTTPHeader + readFile

        tcpSocket.sendall(readFile.encode())
        tcpSocket.close()

        pass

    def __init__(self, args):
        print('Web Proxy starting on port: %i...' % (args.port))

        webServer = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        webServer.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)

        self.address = ("",args.port)
        webServer.bind(self.address)
        webServer.listen(1)

        self.recived,self.newAdress = webServer.accept()

        self.proxyHandler(self.recived, self.newAdress)
        #self.handleRequest(self.recived)

        webServer.close()



if __name__ == "__main__":
    args = setupArgumentParser()
    args.func(args)

