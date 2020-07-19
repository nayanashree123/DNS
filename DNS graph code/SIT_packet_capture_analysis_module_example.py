#!/usr/bin/env python
#Usage           :python SIT_packet_capture_analysis_module_example.py <pcap_file> 
#description     :Module used to display the entire protocol list and heirarchy within the PCAP along with plotting packet size graph. The filter used for the same is "-qz io,phs". Output file generated is Protocol_Hierarchy.html
#date            :20200616
#version         :0.1
#notes           :
#python_version  :3.7.3
#==============================================================================

import sys
import logging
import subprocess
import pyshark
from datetime import datetime
from flask import Flask, request, redirect, url_for
from pygal import XY
from pygal.style import LightGreenStyle

logging.getLogger().setLevel(logging.DEBUG)
logger = logging.getLogger(__name__)





def plot(filename):
    pkt_sizes = []
    cap = pyshark.FileCapture(filename, only_summaries=True)
   # cap = pyshark.FileCapture(filename)
    for packet in cap:
        
         #print(type(packet.time))
         l=float(packet.time)
         pkt_sizes.append((float(packet.start),float(packet.time)))
           
    pkt_size_chart = XY(width=600, height=500, style=LightGreenStyle, explicit_size=True)
    pkt_size_chart.title = 'DNS response time'
  
    pkt_size_chart.add('Time', pkt_sizes)
    chart = pkt_size_chart.render()
    print(chart)
    html = """{}""".format(chart)
    return html 

def main():
	
    if len(sys.argv) != 2:
    	logger.error('Insufficient arguments')
    	print("Usage: <script_name>.py <pcap_file>")
    	sys.exit(1)

    filename = sys.argv[1]
   #  op = task(filename)
    op2 = plot(filename)
    htmlFile = open('Protocol_Hierarchy.html', 'w')
    htmlFile.write('<pre>')
    # htmlFile.write(op)
    htmlFile.write(op2)
    htmlFile.write('/<pre>')


if __name__=="__main__":
    main()
