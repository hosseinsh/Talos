#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2014, Institute for Pervasive Computing, ETH Zurich.
# All rights reserved.
#
# Author: Andreas Dröscher <contiki@anticat.ch>
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. Neither the name of the Institute nor the names of its contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#

import sys, glob, time, serial, socket;

class TCPWrapper:
  """Wrapper that emulates Serial on TCP"""
  def __init__(self, ip, port):
    self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
    self.socket.connect((ip, port));
    
  def write(self, byte):
    self.socket.send(byte);
    
  def read(self, size):
    buf = ""
    while len(buf) < size:
      buf += self.socket.recv(size-len(buf));
    return buf;
   
  def close(self):
    self.socket.close();

class TestInterface:
  """TestInterface Client Library"""
  magic          = 0xAAAAAAAA;
  app            = 0;
  function       = 0;
  payload_length = 0;
  payload        = [0];
  serialport     = None;
  
  #Enums copied from test-interface.h
  RES_RESULT_CODE         =  0
  APP_DEBUG               =  1
  APP_MANAGEMENT          =  2
  APP_TIMER               =  3
  APP_SHA256              =  4
  APP_CCM                 =  5
  APP_ECC                 =  6
  APP_TINYDTLS            =  7
  APP_AES                 =  8
  APP_PAILLER             =  9
  APP_ELGAMAL             = 10
  APP_BLOWFISH            = 11  
  
  RES_SUCCESS             =  0
  RES_ERROR               = -1
  RES_WRONG_PARAMETER     = -2
  RES_UNKOWN_APPLICATION  = -3
  RES_UNKOWN_FUNCTION     = -4
  RES_REBOOT              = -5
  RES_NOT_IMPLEMENTED     = -6
  RES_ALGORITHM_FAILED    = -7
  RES_OUT_OF_MEMORY       = -8

  LVL_DEBUG               =  1
  LVL_INFO                =  2
  LVL_WARNING             =  3
  LVL_ERROR               =  4

  REBOOT                  =  1
  SWITCH_PKA              =  2
  SWITCH_CRYPTO           =  3
  READ_BUFFER             =  4
  WRITE_BUFFER            =  5
 
  def getResult(self, result_code):
    return {
        self.RES_SUCCESS:           "SUCCESS",
        self.RES_ERROR:             "ERROR",
        self.RES_WRONG_PARAMETER:   "WRONG PARAMETER",
        self.RES_UNKOWN_APPLICATION:"UNKOWN APPLICATION",
        self.RES_UNKOWN_FUNCTION:   "UNKOWN FUNCTION",
        self.RES_REBOOT:            "REBOOT",
        self.RES_NOT_IMPLEMENTED:   "FUNCTION NOT IMPLEMENTED",
        self.RES_ALGORITHM_FAILED:  "ALGORITHM FAILED",
        self.RES_OUT_OF_MEMORY:     "OUT OF MEMORY",
        }.get(result_code-256,      "%s" % result_code)
  
  def getDebugLevel(self, level):
    return {
        self.LVL_DEBUG:   "DEBUG",
        self.LVL_INFO:    "INFO",
        self.LVL_WARNING: "WARNING",
        self.LVL_ERROR:   "ERROR",
        }.get(level,      "UNKNOWN")

  def connect(self, ip, port):
    self.serialport = TCPWrapper(ip, port)

    if self.serialport is None:
      raise IOError("Could not open connection");
        
  def open(self, port = None, speed = None):
    """Open the Serial Port"""
    #Find USB-Port
    if port is None:
      glob_list = glob.glob("/dev/tty.usbserial*");
      if len(glob_list) > 0:
        port = glob_list[0];
    
    if port is None:
      raise IOError("Could not find serial port");
    
    if speed is None:
      speed = 460800;
    
    #Connect to Target
    self.serialport = serial.Serial(port, speed,
                                    bytesize = serial.EIGHTBITS,
                                    stopbits = serial.STOPBITS_ONE,
                                    parity   = serial.PARITY_NONE,
                                    timeout  = 5);

    if self.serialport is None:
      raise IOError("Could not open serial port");
                                    
  def close(self):
    """Close the Serial Port"""
    self.serialport.close();
  
  def reset(self):
    """Reset Target"""
    if self.serialport is None:
      self.open();
    if isinstance(self.serialport, TCPWrapper):
      self.writePacket(self.APP_MANAGEMENT, self.REBOOT, 0, []);
    else:
      self.serialport.setRTS(1);
      self.serialport.setDTR(1);
      self.serialport.setDTR(0);
    
  def readByte(self):
    """Returns next Byte"""
    byte = self.serialport.read(1);
    if len(byte) == 0:
      raise IOError("Receive Timeout");
    return byte;
  
  def readOctet(self):
    """Returns next Octet"""
    return ord(self.readByte());
  
  def readShort(self):
    """Returns next short in host byte order"""
    value  = self.readOctet() << 8;
    value |= self.readOctet();
    return value;
    
  def readLong(self):
    """Returns next long in host byte order"""
    value   = self.readOctet() <<  0;
    value  |= self.readOctet() <<  8;
    value  |= self.readOctet() << 16;
    value  |= self.readOctet() << 24;
    return value;
    
  def readPacket(self):
    """Returns the next Packet"""

    #Wait for Magic Header, output everything else
    byte = self.readByte();
    while ord(byte) != 0xAA:
      sys.stderr.write(byte);
      byte = self.readByte();
    count = 1;
    while count != 4:
      byte = self.readByte();
      if ord(byte) == 0xAA:
        count = count + 1;
      else:
        raise IOError("Unexpected Input");
    
    #Read Packet
    self.app            = self.readOctet();
    self.function       = self.readOctet();
    self.payload_length = self.readShort();
    self.payload        = self.serialport.read(self.payload_length);
    if len(self.payload) != self.payload_length:
      raise IOError("Receive Timeout");
    #print " 0x".join(x.encode('hex') for x in self.payload)
    return self.payload;

  def readResponse(self):
    while 1: #Wait for Response output everything else
      payload = self.readPacket();
      if self.app == self.APP_DEBUG:
        sys.stderr.write("%s: %s" % (self.getDebugLevel(self.function), payload));
      else:
        return self.function;
  
  def writeOctet(self, value):
    if isinstance(value, int):
      self.serialport.write(chr(value));
    else:
      self.serialport.write(chr(ord(value)));
  
  def writeShort(self, value):
    self.writeOctet((value >> 8) & 0xff);
    self.writeOctet((value >> 0) & 0xff);
    
  def writeLong(self, value):
    self.writeOctet((value >> 24) & 0xff);
    self.writeOctet((value >> 16) & 0xff);
    self.writeOctet((value >>  8) & 0xff);
    self.writeOctet((value >>  0) & 0xff);
     
  def writePacket(self, app, function, payload_length = 0, payload = []):
    #Check payload length
    if payload_length > len(payload):
      raise RuntimeError("payload_length (=%d) > len(payload) (=%d)" % (payload_length, len(payload)))
    
    #Output Packet
    self.serialport.write("\xAA\xAA\xAA\xAA"); #Send Magic Header
    self.writeOctet(app);
    self.writeOctet(function);
    self.writeShort(payload_length);
    for i in range(0, payload_length):
      self.writeOctet(payload[i]);
    
  def executeCommand(self, app, function, payload_length = 0, payload = []):
    self.writePacket(app, function, payload_length, payload);
    if self.readResponse() != self.RES_SUCCESS:
      raise RuntimeError("ExecuteCommand Returned: %s" % self.getResult(self.function));
    return self.function;
  
  def uploadData(self, data_length = 0, data = []):
    if data_length > len(data):
      raise RuntimeError("data_length (=%d) > len(data) (=%d)" % (data_length, len(data)));
    for x in range(0, data_length, 256):
      payload = [0]*4;
      self.setShort(payload, 0, x);
      if(data_length - x < 256):
        self.setShort(payload, 2, data_length-x);
        self.executeCommand(self.APP_MANAGEMENT, self.WRITE_BUFFER, data_length-x + 4, payload + list(data[x:]));
      else:
        self.setShort(payload, 2, 256);
        self.executeCommand(self.APP_MANAGEMENT, self.WRITE_BUFFER, 260, payload + list(data[x:(x+256)]));
        
  def downloadData(self, data_length):
    data = "";
    for x in range(0, data_length, 256):
      payload = [0]*4;
      self.setShort(payload, 0, x);
      if(data_length - x < 256):
        self.setShort(payload, 2, data_length-x);
        self.executeCommand(self.APP_MANAGEMENT, self.READ_BUFFER, 4, payload);
        data = data + self.payload;
      else:
        self.setShort(payload, 2, 256);
        self.executeCommand(self.APP_MANAGEMENT, self.READ_BUFFER, 4, payload);
        data = data + self.payload;
    return data;
  
  def getShort(self, payload, index):
    """Utility function to read a short from the payload"""
    value  = ord(payload[index+0]) << 0;
    value |= ord(payload[index+1]) << 8;
    return value;
  
  def getLong(self, payload, index):
    """Utility function to read a long from the payload"""
    value  = ord(payload[index+0]) << 24;
    value |= ord(payload[index+1]) << 16;
    value |= ord(payload[index+2]) <<  8;
    value |= ord(payload[index+3]) <<  0;
    return value;

  def setShort(self, payload, index, value):
    """Utility function to write a long to tpayloadayload"""
    payload[index+0] = (value >> 8) & 0xff;
    payload[index+1] = (value >> 0) & 0xff;

  def setLong(self, payload, index, value):
    """Utility function to write a short to the payload"""
    payload[index+0] = (value >> 24) & 0xff;
    payload[index+1] = (value >> 16) & 0xff;
    payload[index+2] = (value >>  8) & 0xff;
    payload[index+3] = (value >>  0) & 0xff;

