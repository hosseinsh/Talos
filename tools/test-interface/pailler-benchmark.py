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

import sys, os, binascii, random

from TerminalApplication import TerminalApplication
from TestInterface.MeasurementWriter import MeasurementWriter
from TestInterface.AppPailler import AppPailler

KEY_P = "33760457E3935094C0D70FED86FB3614CFDDD6FA7F1E68766071DF952EAD7E25F7FAEC7051219209BC72BC90D066BAB6BFFDD413E9965B14C3D790EAED7B34A9"
KEY_Q = "9E027D7989D2FD821B6D3B4A7643BCDE65AB5B2AE8035C5BC981A97819118E35324341DD2D94062980F98215B6EBD2A2641264377A61647162EA0DE6F404BC3F"

class PaillerApplication(TerminalApplication):
  def define_arguments(self, parser):
    parser.add_argument("-n", "--cycles", dest="cycles", metavar="n", help="run benchmark n times (default: 1)", default=1);
    parser.add_argument("-o", "--output", dest="output", metavar="o", help="save measurements (JSON) into o");
    parser.add_argument(                  dest="min",                 help="min in bytes",);
    parser.add_argument(                  dest="max",                 help="max in bytes",);
    parser.add_argument(                  dest="step",                help="step in bytes",);

  def instantiate_interface(self, args):
    return AppPailler();

  def execute_test(self, client, args):
    #Prepare Measurement Writer
    measurements = MeasurementWriter(args.output)
    
    #Download Key
    client.setKey(binascii.a2b_hex(KEY_P), binascii.a2b_hex(KEY_Q));
    client.generate();

    #Run Tests
    nb = 1;
    for size in range(int(args.min), int(args.max)+1, int(args.step)):
      sys.stdout.write("Running Test (Index: %d): " % nb);
      nb = nb+1;

      for i in range(0, int(args.cycles)):
        if(i % 50 == 0):
          sys.stdout.write(".");
          sys.stdout.flush();

        #Generate random PlainText
        input  = ("%x" % random.getrandbits(size*8)).zfill(size*2);
        input = binascii.a2b_hex(input);
        client.setPlainText(input);

        client.clearTimer();
        client.encrypt();
        measurement = client.readMultiValueMeasurements();
        measurements.add("%d-enc"      % size, {1: measurement[1][0]});

        client.clearTimer();
        client.decrypt();
        measurement = client.readMultiValueMeasurements();
        measurements.add("%d-dec"      % size, {1: measurement[1][0]});

        #Only Verify Result if benchmark is not running
        if args.output is None:
          payload = client.getPlainText()[0:len(input)];
          if payload != input:
            raise RuntimeError("Test Vector failed.");

      sys.stdout.write(" success.\n");

    measurements.save();
    return 0;

if __name__ == "__main__":
  app = PaillerApplication();
  sys.exit(app.main());
