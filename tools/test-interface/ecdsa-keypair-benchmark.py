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
from TestInterface.AppECC import AppECC

class EccApplication(TerminalApplication):
  def define_arguments(self, parser):
    parser.add_argument("-g", "--generator", dest="gen",      action="store_true", help="use mul_gen instead of mul");
    parser.add_argument("-n", "--cycles",    dest="cycles",   metavar="n",         help="run benchmark n times (default: 1)", default=1);
    parser.add_argument("-o", "--output",    dest="output",   metavar="o",         help="save measurements (JSON) into o");
    parser.add_argument('-s', "--section",   dest="sections", metavar="s",         help="section(s) to use i.e, \"[P-192]\"", action="append", required=True);
    parser.add_argument(                     dest="file",                          help="CAVS response files");

  def instantiate_interface(self, args):
    return AppECC();

  def execute_test(self, client, args):
    #Prepare Measurement Writer
    measurements = MeasurementWriter(args.output)

    #Run Tests
    test_vectors = CavsReader(args.file, None, ["d", "Qx", "Qy"]);
    for section in args.sections:
        #Select Curve Once
        test_vectors.selectSection(section);
        client.selectCurve(section);
        nb = 1;

        #for Each Entry
        for entry in test_vectors:
          sys.stdout.write("Running Test (Section: %s, Index: %d): " % (section, nb));
          nb = nb+1;

          #Calculate Public Key cycle times
          for i in range(0, int(args.cycles)):
            sys.stdout.write(".");
            sys.stdout.flush();

            client.clearTimer();
            if args.gen:
              client.calculatePublicKey(entry["d"]);
            else:
              client.multiply(entry["d"], client.curve["Gx"], client.curve["Gy"]);              
            if entry["Qx"] != client.getBigNum(client.payload, client.getNumSize()*4*0):
              raise RuntimeError("Test Vector: '%s' failed." % entry["d"]);
            if entry["Qy"] != client.getBigNum(client.payload, client.getNumSize()*4*1):
              raise RuntimeError("Test Vector: '%s' failed." % entry["d"]);

            #Add Measurement
            measurement = {nb-1: client.readMeasurements()[1]};
            measurements.add("%s" % (client.getNumSize()*4*8), measurement);
          sys.stdout.write(" success.\n");

    measurements.save();
    return 0;

if __name__ == "__main__":
  app = EccApplication();
  sys.exit(app.main());
