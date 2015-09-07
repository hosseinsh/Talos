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

import sys, os, random, binascii

from TerminalApplication import TerminalApplication
from TestInterface.AppAES import AppAES

class AesApplication(TerminalApplication):
  def define_arguments(self, parser):
    parser.add_argument(                  dest="min",  help="min in bytes",);
    parser.add_argument(                  dest="max",  help="max in bytes",);
    parser.add_argument(                  dest="step", help="step in bytes",);
    parser.add_argument("-o", "--output", dest="dst",  help="file to save test data to (default: stdout)", metavar="o");

  def instantiate_interface(self, args):
    return AppAES();

  def execute_test(self, client, args):
    #Open destination
    dst = sys.stdout;
    if args.dst is not None: 
      dst = open(args.dst, "w");
      
    #Generate test data
    random.seed();
    dst.write("[AES]\n");

    for i in range(int(args.min), int(args.max)+1, int(args.step)):
      client.clearTimer();
      
      #Write Input
      key = ("%x" % random.getrandbits(16*8)).zfill(16*2);
      iv  = ("%x" % random.getrandbits(16*8)).zfill(16*2);
      msg = ("%x" % random.getrandbits(i*8)).zfill(i*2);
      dst.write("Count = %d\n"  % i);
      dst.write("Key = %s\n"  % key);
      dst.write("IV = %s\n"  % iv);
      dst.write("Msg = %s\n"  % msg);
      
      client.setKey(binascii.a2b_hex(key))
      client.setIV(binascii.a2b_hex(key))
      client.uploadMessage(binascii.a2b_hex(msg));
      
      #Calculate and write CBC 
      client.switchToCBCMode();
      client.encrypt(i);
      ct_length = client.getLong(client.payload, 0);
      ct = binascii.b2a_hex(client.downloadData(ct_length));
      dst.write("CBC = %s\n"  % ct);
            
      #Calculate and write ECB
      client.switchToECBMode();
      client.encrypt(i);
      ct_length = client.getLong(client.payload, 0);
      ct = binascii.b2a_hex(client.downloadData(ct_length));
      dst.write("ECB = %s\n"  % ct);
      
      #Calculate and write CTR
      client.switchToCTRMode();
      client.encrypt(i);
      ct_length = client.getLong(client.payload, 0);
      ct = binascii.b2a_hex(client.downloadData(ct_length));
      dst.write("CTR = %s\n\n"  % ct);
    return 0;

if __name__ == "__main__":
  app = AesApplication();
  sys.exit(app.main());
