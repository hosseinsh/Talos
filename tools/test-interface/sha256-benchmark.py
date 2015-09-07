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

import sys, binascii

from TerminalApplication import TerminalApplication
from TestInterface.CavsReader import CavsReader
from TestInterface.MeasurementWriter import MeasurementWriter
from TestInterface.AppSha256 import AppSha256

class Sha256Application(TerminalApplication):
  def define_arguments(self, parser):
    parser.add_argument("-n", "--cycles", dest="cycles", metavar="n", help="run benchmark n times (default: 1)", default=1);
    parser.add_argument("-o", "--output", dest="output", metavar="o", help="save measurements (JSON) into o");
    parser.add_argument(                  dest="file",                help="CAVS response files",);

  def instantiate_interface(self, args):
    return AppSha256();

  def execute_test(self, client, args):
    #Prepare Measurement Writer
    measurements = MeasurementWriter(args.output)

    #Run Tests
    test_vectors = CavsReader(args.file, "[L = 32]", ["Len", "Msg", "MD"]);
    nb = 1;
    for entry in test_vectors:
      sys.stdout.write("Running Test (Index: %d): " % nb);
      nb = nb+1;
      
      #Upload Data Once
      client.uploadData(int(entry["Len"])/8, binascii.a2b_hex(entry["Msg"]));

      #Calculate Hash cycle times
      for i in range(0, int(args.cycles)):
        if(i % 50 == 0):
          sys.stdout.write(".");
          sys.stdout.flush();

        client.clearTimer();
        client.calculateHash(int(entry["Len"])/8,);
        if entry["MD"] != binascii.b2a_hex(client.payload):
          raise RuntimeError("Test Vector: '%s' failed." % entry["Msg"]);

        #Add Measurement
        measurements.add("%s" % (int(entry["Len"])/8), client.readMeasurements());
      sys.stdout.write(" success.\n");

    measurements.save();
    return 0;

if __name__ == "__main__":
  app = Sha256Application();
  sys.exit(app.main());
