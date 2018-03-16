# !/usr/bin/python
# -*- coding: utf-8 -*-

# FollowTcpStream - Comparable to Wireshark's functionality but including un-chunking and un-gzipping.
#
# Author: Christian Wojner
# Credits: Influenced by Brian Maloneys PCAP_tools (https://github.com/Beercow/ProcDOT-Plugins/tree/master/PCAP_tools)
#
# Dependencies:
# - TcpFlow 1.4

# Example: FollowTcpStream.py -i 10.0.2.15:1067 -p 80 -o "C:\Users\chrisu\AppData\Local\Temp\malware\FollowTcpStream.out" "data\test.pcap"
# Example: FollowTcpStream.py -i 10.0.2.15:1067 -p 80 -o "C:\Users\chrisu\AppData\Local\Temp\malware\FollowTcpStream.out" "C:\Users\chrisu\Documents\cert.at\Vorträge\LKOOE\Logs\Scripts.pcap"

import argparse
import os
import sys
import subprocess as sub
import zlib
import re
import binascii


# Cross-platform!
if (os.name == "nt"):
    isWindows = True
    isLinux = False
else:
    isWindows = False
    isLinux = True

gl_TestRunOutput = []
gl_TestRun = False

gl_OutFile = ""
gl_Verbose = False
gl_ChronologicalOrder = False
gl_NoMetaInformation = False
gl_NoSeparators = False
gl_NoHttpHeaders = False


# A management class for redirecting the output according to the arguments provided
class OutputWriter:
    FirstWrite = True
    FooterPending = False

    def normal(self, text):
        global gl_TestRunOutput

        if (self.FirstWrite):
            self.FirstWrite = False
            gl_TestRunOutput = []
            if (not gl_NoSeparators):
                self.normal('\x01[FTS]> HEADER <[FTS]\x02\n\n')
        if gl_TestRun:
            gl_TestRunOutput.append(text)
            gl_TestRunOutput.append("\n")
        elif gl_OutFile == "":
            print(text)
        else:
            if (isinstance(text, bytes)):
                open(gl_OutFile, 'ab').write(text)
            else:
                open(gl_OutFile, 'at').write(text + "\n")

    def verbose(self, text):
        if (gl_Verbose):
            self.normal(text)

    def finish(self):
        if (not self.FirstWrite):
            if (not gl_NoSeparators):
                self.normal('\n\n\x01[FTS]> FOOTER <[FTS]\x02')


class Flow:
    Id = ""
    Timestamp = ""
    ConnectionNumber = ""
    SrcIpAddress = ""
    SrcPort = ""
    DstIpAddress = ""
    DstPort = ""
    Data = ""
    isHttpRequest = False
    HttpRequestAction = ""
    isHttpResponse = False
    HttpRequestFlow = 0
    HttpResponseFlow = 0
    isHttp = False
    HttpHeader = ""
    isGzipped = False
    isChunked = False
    NextFlow = 0
    OutputPending = True


# parse out tcp flow for IP
def parseFlow(pcapFile, ipAddress = b"", tcpPort = b""):
    out = OutputWriter()

    if (isWindows):
        p = sub.Popen(['tcpflow', '-T %T--%A:%a-%B:%b--%N', '-cgD', '-r', pcapFile], stdout=sub.PIPE, stderr=sub.PIPE)
    else:
        p = sub.Popen(['tcpflow', '-T %T--%A:%a-%B:%b--%N', '-cJD', '-r', pcapFile], stdout=sub.PIPE, stderr=sub.PIPE)
    stdout, stderr = p.communicate()
    stdout = stdout.replace(b'\r\n', b'\n')

    if ipAddress not in stdout:
        out.normal("No tcp flows found for " + ipAddress.decode())
    elif tcpPort not in stdout:
        out.normal("No tcp flows found for " + tcpPort[1:].decode())
    else:
        flowsCacheRoot = 0
        flowsCacheLast = 0
        flows = re.findall(b'\x1b\[0;3[14]m\s*(\S+)\s\n(.*?)\x1b\[0m', stdout, re.DOTALL)
        # flows = iter(flows)
        out.verbose("Building flows ...")
        out.verbose("")
        flowBuilder = {}
        for meta, hexdump in flows:
            flow = Flow()
            flow.Timestamp, \
            flow.SrcIpAddress, \
            flow.SrcPort, \
            flow.DstIpAddress, \
            flow.DstPort, \
            flow.ConnectionNumber = re.search(b'^(.+?)--(.+?):(.+?)-(.+?):(.+?)--(.+?):', meta).groups()
            flow.Id = flow.SrcIpAddress + b":" + flow.SrcPort + b"-" + flow.DstIpAddress + b":" + flow.DstPort

            # Unhexdumpify data
            hexdumprows = re.findall(b'^[0-9a-f]+: ((?:[0-9a-f]{4} |[0-9a-f]{2} )+).*?$', hexdump, re.MULTILINE)
            data = b""
            for hexdumprow in hexdumprows:
                data = b''.join([data, hexdumprow])
            data = data.replace(b" ", b"")
            flow.Data = binascii.unhexlify(data)

            flowId = flow.Id
            flowIdInv = flow.DstIpAddress + b":" + flow.DstPort + b"-" + flow.SrcIpAddress + b":" + flow.SrcPort

            if (re.match(b'^(?:GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH)\s.*', flow.Data)):
                flow.isHttp = True
                flow.isHttpRequest = True
                flow.HttpRequestAction = flow.Data[:flow.Data.find(b"\r")]
                if (flowId in flowBuilder):
                    flowBuilder.pop(flowId)
                if (flowIdInv in flowBuilder):
                    flowBuilder.pop(flowIdInv)

            if (re.match(b'^HTTP/.*', flow.Data)):
                flow.isHttp = True
                flow.isHttpResponse = True
                if (flowIdInv in flowBuilder):
                    flow.HttpRequestFlow = flowBuilder[flowIdInv]
                    flowBuilder[flowIdInv].HttpResponseFlow = flow

            if (flow.isHttp):
                flow.HttpHeader, flow.Data = re.search(b'^(.*?)\r\n\r\n(.*)$', flow.Data, re.DOTALL).groups()
                flow.HttpHeader = flow.HttpHeader.replace(b'\r\n', b'\n')
                if (flow.isHttpResponse):
                    flow.isGzipped = re.search(b'^content-encoding:\s.*?gzip.*?$', flow.HttpHeader, re.IGNORECASE | re.MULTILINE) != None
                    flow.isChunked = re.search(b'^transfer-encoding:\s.*?chunked.*?$', flow.HttpHeader, re.IGNORECASE | re.MULTILINE) != None

            if (flowIdInv in flowBuilder):
                flowBuilder.pop(flowIdInv)

            if (flowId in flowBuilder):
                mainflow = flowBuilder[flowId]
                mainflow.Data = b''.join([mainflow.Data, flow.Data])
                out.verbose("    Appending " + str(len(flow.Data)) + " bytes to mainflow " + mainflow.Id.decode())
            else:
                flowBuilder[flowId] = flow
                out.verbose("    Adding new mainflow " + flow.Id.decode() + " (" + str(len(flow.Data)) + " bytes)")
                if (not flowsCacheRoot):
                    flowsCacheRoot = flow
                    flowsCacheLast = flow
                else:
                    flowsCacheLast.NextFlow = flow
                    flowsCacheLast = flow

        out.verbose("")
        out.verbose("")

        # Post-Processing flows ...
        if (flowsCacheRoot):
            out.verbose("Post-Processing flows ...")
            out.verbose("")

            flow = flowsCacheRoot
            while (flow):
                if (gl_Verbose):
                    out.verbose("    " + flow.Id.decode())
                    if (flow.isHttp and flow.isHttpRequest):
                        out.verbose("        isHttp (Request: " + flow.HttpRequestAction.decode() + ")")
                    if (flow.isHttp and flow.isHttpResponse):
                        out.verbose("        isHttp (Response)")
                    if (flow.isChunked):
                        out.verbose("        isChunked")
                    if (flow.isGzipped):
                        out.verbose("        isGzipped")

                # Un-chunking ...
                if (flow.isChunked):
                    # if (flow.Id == b"069.004.231.030:00080-192.168.001.010:49190"):
                    #     print("Hallo")
                    #     out.verbose(b"[" + flow.Data + b"]")
                    #     out.verbose("")
                    chunkCounter = 0
                    chunkedData = flow.Data
                    flow.Data = b""
                    while (len(chunkedData)):
                        chunkCounter += 1
                        res = re.search(b'^([0-9a-fA-F]+)[^\r\n]*\r\n(.*)$', chunkedData, re.DOTALL)
                        if (res):
                            chunkSizeHex, chunkedData = res.groups()
                            chunkSizeHex = chunkSizeHex.decode()
                            chunkSize = int(chunkSizeHex, 16)
                            if (chunkSize):
                                out.verbose("        " + "Merging chunk #" + str(chunkCounter) + ": " + str(chunkSize) + " (" + chunkSizeHex + ") Bytes")
                                flow.Data = b''.join([flow.Data, chunkedData[:chunkSize]])
                                chunkedData = chunkedData[chunkSize:]
                                chunkedData = chunkedData[2:]
                            else:
                                chunkedData = ""
                        else:
                            out.verbose("        " + "Warning: Parsing error! (Note: Usually due to some special situation in the PCAP leading to interpretation mistakes in Tcpflow.)")
                            out.verbose("---- Content already merged ----")
                            out.verbose(b"[")
                            out.verbose(flow.Data)
                            out.verbose(b"]")
                            out.verbose("\n--------------------------------")
                            out.verbose("-------- Content pending -------")
                            out.verbose(b"[")
                            out.verbose(chunkedData)
                            out.verbose(b"]")
                            out.verbose("\n--------------------------------")
                            flow.Data = b''.join([flow.Data, chunkedData])
                            break

                # Un-gzipping ...
                if (flow.isGzipped):
                    try:
                        zlo = zlib.decompressobj(16 + zlib.MAX_WBITS)
                        sizeCompressed = len(flow.Data)
                        flow.Data = zlo.decompress(flow.Data)
                        sizeDecompressed = len(flow.Data)
                        out.verbose("        " + "Decompressing: " + str(sizeCompressed) + " bytes -> " + str(sizeDecompressed) + " bytes")
                    except Exception as exc:
                        out.verbose("        " + 'DECOMPRESSION ERROR: %s' % exc)

                # Replacing non-printables ...
                if (gl_Verbose):
                    c = flow.Data.count(b'.')
                else:
                    c = 0
                flow.Data = re.sub(b'[^!\"#\$%&\'\(\)\*\+,-\./0-9:;<=>\?@A-Z\[\]\^_`a-z\{\|\}\\\~\t\n\r ]', b'.', flow.Data)
                out.verbose("        " + "Replacing non-printables: " + str(flow.Data.count(b'.') - c) + " occurrences")

                # Jump to next flow ...
                flow = flow.NextFlow

            out.verbose("")
            out.verbose("")
            out.verbose("Effective output ...")
            out.verbose("")

            # Output ...
            flow = flowsCacheRoot
            while (flow):
                if (ipAddress in flow.Id and tcpPort in flow.Id):
                    if (flow.OutputPending):
                        # HTTP request/response pair ...
                        if (flow.isHttp and flow.isHttpRequest and flow.HttpResponseFlow):
                            if (not gl_NoSeparators):
                                if (not gl_NoMetaInformation):
                                    out.normal("\x01[FTS]> HTTP_PAIR_REQUEST: " + flow.SrcIpAddress.decode() + ":" + flow.SrcPort.decode() + " - " + flow.DstIpAddress.decode() + ":" + flow.DstPort.decode() + " <[FTS]\x02\n")
                                else:
                                    out.normal("\x01[FTS]> HTTP_PAIR_REQUEST <[FTS]\x02\n")
                            out.normal(flow.HttpHeader.decode())
                            out.normal("")
                            if (flow.Data != b""):
                                out.normal(flow.Data.decode())
                            flow.OutputPending = False
                            if (not gl_ChronologicalOrder):
                                flowr = flow.HttpResponseFlow
                                if (not gl_NoSeparators):
                                    if (not gl_NoMetaInformation):
                                        out.normal("\x01[FTS]> HTTP_PAIR_RESPONSE: " + flowr.SrcIpAddress.decode() + ":" + flowr.SrcPort.decode() + " - " + flowr.DstIpAddress.decode() + ":" + flowr.DstPort.decode() + " <[FTS]\x02\n")
                                    else:
                                        out.normal("\x01[FTS]> HTTP_PAIR_RESPONSE <[FTS]\x02\n")
                                out.normal(flowr.HttpHeader.decode())
                                out.normal("")
                                out.normal(flowr.Data.decode())
                                flowr.OutputPending = False

                        # HTTP request without response ...
                        elif (flow.isHttp and flow.isHttpRequest and not flow.HttpResponseFlow):
                            if (not gl_NoSeparators):
                                if (not gl_NoMetaInformation):
                                    out.normal("\x01[FTS]> HTTP_REQUEST: " + flow.SrcIpAddress.decode() + ":" + flow.SrcPort.decode() + " - " + flow.DstIpAddress.decode() + ":" + flow.DstPort.decode() + " <[FTS]\x02\n")
                                else:
                                    out.normal("\x01[FTS]> HTTP_REQUEST <[FTS]\x02\n")
                            out.normal(flow.HttpHeader.decode())
                            out.normal("")
                            if (flow.Data != b""):
                                out.normal(flow.Data.decode())
                            flow.OutputPending = False

                        # HTTP response without request ...
                        elif (flow.isHttp and flow.isHttpResponse and not flow.HttpRequestFlow):
                            if (not gl_NoSeparators):
                                if (not gl_NoMetaInformation):
                                    out.normal("\x01[FTS]> HTTP_RESPONSE: " + flow.SrcIpAddress.decode() + ":" + flow.SrcPort.decode() + " - " + flow.DstIpAddress.decode() + ":" + flow.DstPort.decode() + " <[FTS]\x02\n")
                                else:
                                    out.normal("\x01[FTS]> HTTP_RESPONSE <[FTS]\x02\n")
                            out.normal(flow.HttpHeader.decode())
                            out.normal("")
                            if (flow.Data != b""):
                                out.normal(flow.Data.decode())
                            flow.OutputPending = False

                        # Any non-HTTP flow ...
                        elif (flow.isHttp and flow.isHttpResponse and not flow.HttpRequestFlow):
                            if (not gl_NoSeparators):
                                if (not gl_NoMetaInformation):
                                    out.normal("\x01[FTS]> NON_HTTP: " + flow.SrcIpAddress.decode() + ":" + flow.SrcPort.decode() + " - " + flow.DstIpAddress.decode() + ":" + flow.DstPort.decode() + " <[FTS]\x02\n")
                                else:
                                    out.normal("\x01[FTS]> NON_HTTP <[FTS]\x02\n")
                            out.normal(flow.Data.decode())
                            flow.OutputPending = False

                flow = flow.NextFlow

            out.finish()


# convert TCP port into tcpflow format
def parseTcpPort(tcpPort):
    if (not re.match(r"0*?((?:0|[0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]))", tcpPort)):
        e = str("[ERROR] Not a valid TCP port number!\n")
        print(e)
        sys.exit(2)

    if tcpPort == "":
        return ":" + tcpPort
    else:
        return ":" + ("0000" + tcpPort)[-5:]


# convert IP address into tcpflow format
def parseIpAddress(ipAddress):
    if (not re.match(r"^(0*?(0|[1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.0*?(0|[1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.0*?(0|[1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.0*?(0|[1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(?::0*?((?:0|[0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])))?)$", ipAddress)):
        sys.stderr.normal("[ERROR] Not a valid IP address!\n")
        sys.exit(1)

    if ipAddress == "":
        return ipAddress
    else:
        ipAddress, b1, b2, b3, b4, tcpPort = re.search(r"^(0*?(0|[1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.0*?(0|[1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.0*?(0|[1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.0*?(0|[1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(?::0*?((?:0|[0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])))?)$", ipAddress).groups()
        b1 = '00' + (b1)
        b2 = '00' + (b2)
        b3 = '00' + (b3)
        b4 = '00' + (b4)
        if (not tcpPort):
            tcpPort = ""
        else:
            tcpPort = parseTcpPort(tcpPort)
        ipAddress = b1[-3:] + '.' + b2[-3:] + '.' + b3[-3:] + '.' + b4[-3:] + tcpPort
        return ipAddress


def checkTcpflowVersion():
    try:
        p = sub.Popen(['tcpflow', '-V'], stdout=sub.PIPE, stderr=sub.PIPE)
        check = p.communicate()[0]
        if b'tcpflow 1.' not in check.lower() and b'tcpflow 2.' not in check.lower():
            e = str("[ERROR] Please download 1.0 or higer\nDownload: https://github.com/simsong/tcpflow/")
            print(e)
            sys.exit(3)
    except Exception as e:
        print("[ERROR] TCPflow missing. Please download 1.0 or higer.\nDownload: https://github.com/simsong/tcpflow/")
        print("Exception: ", e)
        sys.exit(4)


def main():
    global gl_OutFile
    global gl_Verbose
    global gl_ChronologicalOrder
    global gl_NoHttpHeaders
    global gl_NoMetaInformation
    global gl_NoSeparators

    checkTcpflowVersion()

    argparser = argparse.ArgumentParser()
    argparser.add_argument("pcapfile", help="The PCAP file you want to process")
    argparser.add_argument("-c", "--CHRONOLOGICAL_ORDER", action="store_true", help="Print in chronological order instead of keeping HTTP requests and responses together.")
    argparser.add_argument("-H", "--NO_HTTP_HEADERS", action="store_true", help="Suppresses HTTP headers.")
    argparser.add_argument("-i", "--IP_ADDRESS", help="Only include packets sent from or to this IP address (with an optional port separated by ':').")
    argparser.add_argument("-M", "--NO_META_INFORMATION", action="store_true", help="Suppresses meta-information (i.e. IP-addresses, timestamps, ...).")
    argparser.add_argument("-o", "--OUT_FILE", help="Use this file for output instead of stdout.")
    argparser.add_argument("-p", "--TCP_PORT", help="Only include packets sent from or to this TCP port number.")
    argparser.add_argument("-S", "--NO_SEPARATORS", action="store_true", help="Suppresses flow separators.")
    argparser.add_argument("-v", "--VERBOSE", action="store_true", help="Output includes debug information.")
    argparser.add_argument("-V", "--VERSION", action="store_true", help="Print version information.")
    args = argparser.parse_args()

    if (args.VERSION):
        print("FollowTcpStream alpha\n")
    else:
        if args.CHRONOLOGICAL_ORDER:
            gl_ChronologicalOrder = True

        if args.NO_HTTP_HEADERS:
            gl_NoHttpHeaders = True

        ipAddress = b""
        if args.IP_ADDRESS:
            ipAddress = parseIpAddress(args.IP_ADDRESS).encode()

        if args.NO_META_INFORMATION:
            gl_NoMetaInformation = True

        if args.OUT_FILE:
            gl_OutFile = args.OUT_FILE
            if (gl_OutFile != "" and os.path.isfile(gl_OutFile)):
                os.remove(gl_OutFile)

        tcpPort = b""
        if args.TCP_PORT:
            tcpPort = parseTcpPort(args.TCP_PORT).encode()

        if args.NO_SEPARATORS:
            gl_NoSeparators = True

        if args.VERBOSE:
            gl_Verbose = True

        pcapFile = args.pcapfile

        parseFlow(pcapFile, ipAddress, tcpPort)


if __name__ == '__main__':
    main()
