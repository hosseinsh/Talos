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

from TerminalApplication import TerminalApplication
from TestInterface.CavsReader import CavsReader
from TestInterface.MeasurementWriter import MeasurementWriter
from TestInterface.AppCCM import AppCCM

class CcmApplication(TerminalApplication):
  def define_arguments(self, parser):
    parser.add_argument("-n", "--cycles",  dest="cycles",   metavar="n", help="run benchmark n times (default: 1)", default=1);
    parser.add_argument("-o", "--output",  dest="output",   metavar="o", help="save measurements (JSON) into o");
    parser.add_argument('-s', "--section", dest="sections", metavar="s", help="section(s) to use i.e, \"[Alen = 0, Plen = 24, Nlen = 13, Tlen = 8]\"", action="append", required=True);
    parser.add_argument(                   dest="file",                  help="CAVS response files");

  def instantiate_interface(self, args):
    return AppCCM();

  def execute_test(self, client, args):
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
    test_vectors = CavsReader(args.file, None, ["Count", "Adata", "CT", "Result"]);
    for section in args.sections:
        #Select Section, set CCM parameter
        test_vectors.selectSection(section);
        test_vectors.enablePeekOne();
        ccm_param = dict(item.split(" = ") for item in section.strip(" \n\r][").split(", "));
        nb = 1;

        #for Each Entry
        for entry in test_vectors:
          sys.stdout.write("Running Test (Section: %s, Index: %d): " % (section, nb));
          nb = nb+1;

          #Upload data
          entry = dict(ccm_param.items() + entry.items())
          client.setKey(binascii.a2b_hex(entry["Key"]))
          client.uploadMessage(binascii.a2b_hex(entry["CT"]), binascii.a2b_hex(entry["Nonce"]), binascii.a2b_hex(entry["Adata"]));

          #Calculate ciphertext cycle times
          for i in range(0, int(args.cycles)):
            if(i % 50 == 0):
              sys.stdout.write(".");
              sys.stdout.flush();

            client.clearTimer();
            client.decrypt(int(entry["Tlen"]), 15-int(entry["Nlen"]), len(binascii.a2b_hex(entry["CT"])), int(entry["Alen"]))

            #Fetch Payload
            if upload:
              length = client.getLong(client.payload, 0);
              payload = client.downloadData(length);

              if entry["Result"] != "Pass":
                if len(payload) != 0: 
                  raise RuntimeError("Test Vector: '%s' failed." % entry["CT"]);
                else:
                  if entry["Payload"] != binascii.b2a_hex(payload):
                    raise RuntimeError("Test Vector: '%s' failed." % entry["CT"]);
              client.uploadMessage(binascii.a2b_hex(entry["CT"]), binascii.a2b_hex(entry["Nonce"]), binascii.a2b_hex(entry["Adata"]));

            #Add Measurement
            measurement = {nb-1: client.readMeasurements()[1]};
            measurements.add(int(entry["Plen"]), measurement);
          sys.stdout.write(" success.\n");

    measurements.save();
    return 0;

if __name__ == "__main__":
  app = CcmApplication();
  sys.exit(app.main());
