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

import sys, os, binascii

from Crypto.Cipher import AES
from Crypto.Util import Counter

from TerminalApplication import TerminalApplication
from TestInterface.CavsReader import CavsReader
from TestInterface.MeasurementWriter import MeasurementWriter
from TestInterface.AppAES import AppAES

class AesApplication(TerminalApplication):
  def define_arguments(self, parser):
    parser.add_argument("-D", "--decript",  dest="decript", action="store_true", help="decript (default: encrypt)");
    parser.add_argument("-s", "--register", dest="register",action="store_true", help="i/o trough registers (default: DMA)");
    parser.add_argument("-m", "--aes-mode", dest="aes_mode",metavar="n",         help="select AES mode 1: ECB (default) 2: CBC 3:CTR", default=1, type=int);
    parser.add_argument("-n", "--cycles",   dest="cycles",  metavar="n",         help="run benchmark n times (default: 1)", default=1);
    parser.add_argument("-o", "--output",   dest="output",  metavar="o",         help="save measurements (JSON) into o");
    parser.add_argument(                    dest="file",                         help="CAVS response files");

  def instantiate_interface(self, args):
    return AppAES();

  def execute_test(self, client, args):
    #Select AES Mode
    aes_mode = None;
    if args.aes_mode   == 1:
      aes_mode = AES.MODE_ECB;
      client.switchToECBMode();
    elif args.aes_mode == 2:
      aes_mode = AES.MODE_CBC;
      client.switchToCBCMode();
    elif args.aes_mode == 3:
      aes_mode = AES.MODE_CTR;
      client.switchToCTRMode();
    else:
      raise RuntimeError("Unknown AES mode");

    #Select DMA or Register based I/O
    if args.register:
      client.switchToRegister();
    else:
      client.switchToDMA();

    #Switch upload
    upload = False;
    if args.output is None:
      upload = True;
      client.enableUpload();

    #Enable Timer output on GPIOs  
    if args.export:
      client.enableTimerOutput();

    #Prepare Measurement Write
    measurements = MeasurementWriter(args.output)

    #Run Tests
    test_vectors = CavsReader(args.file, "[AES]", ["Count", "Key", "IV", "Msg", "ECB", "CBC", "CTR"]);
    nb = 1;
    for entry in test_vectors:
      sys.stdout.write("Running Test (Index: %d): " % nb);
      nb = nb+1;

      #Upload Data Once
      client.setKey(binascii.a2b_hex(entry["Key"]));
      client.setIV(binascii.a2b_hex(entry["IV"]));
      client.uploadMessage(binascii.a2b_hex(entry["Msg"]));

      #Perform AES-Operation cycle times
      for i in range(0, int(args.cycles)):
        if(i % 50 == 0):
          sys.stdout.write(".");
          sys.stdout.flush();

        client.clearTimer();
        suite = None;
        if args.aes_mode == 3:
          ctr = Counter.new(128, initial_value=int(entry["IV"], 16));
          suite = AES.new(binascii.a2b_hex(entry["Key"]), aes_mode, binascii.a2b_hex(entry["IV"]),  counter=ctr);
        else:
          suite = AES.new(binascii.a2b_hex(entry["Key"]), aes_mode, binascii.a2b_hex(entry["IV"]));

        reference = None;
        if args.decript:
          client.decrypt(len(binascii.a2b_hex(entry["Msg"])));
          reference = suite.decrypt(binascii.a2b_hex(entry["Msg"]));
        else:
          client.encrypt(len(binascii.a2b_hex(entry["Msg"])));
          reference = suite.encrypt(binascii.a2b_hex(entry["Msg"]));

        #Fetch Payload
        if upload:
          length = client.getLong(client.payload, 0);
          payload = client.downloadData(length);
          if payload != reference:
            raise RuntimeError("Test Vector: '%s' failed." % entry["Msg"]);

        #Add Measurement
        measurements.add("%s" % (len(binascii.a2b_hex(entry["Msg"]))), client.readMeasurements());

      sys.stdout.write(" success.\n");

    measurements.save();
    return 0;

if __name__ == "__main__":
  app = AesApplication();
  sys.exit(app.main());
