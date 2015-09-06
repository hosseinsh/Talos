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

import sys, os, random, binascii, hashlib

from TerminalApplication import TerminalApplication
from TestInterface.AppECC import AppECC

class EccApplication(TerminalApplication):
  def define_arguments(self, parser):
    parser.add_argument(dest="num",                   help="number of test cases per key length",);
    parser.add_argument("-o", "--output", dest="dst", help="file to save test data to (default: stdout)", metavar="o");

  def instantiate_interface(self, args):
    return AppECC();

  def execute_test(self, client, args):
    #Open destination
    dst = sys.stdout;
    if args.dst is not None: 
      dst = open(args.dst, "w");

    #Generate test data
    random.seed();
    for key, value in client.CURVE_INFO.iteritems():
      if len(key) < 8:
        continue;
      
      dst.write("%s\n" % key);
      for n in range(0, int(args.num)):
        client.selectCurve(key);
        size = value["size"];
        msg = ("%x" % random.getrandbits(64*8)).zfill(64*2);
        d = ("%x" % random.getrandbits(size*4*8)).zfill(size*4*2);
        b = ("%x" % random.getrandbits(size*4*8)).zfill(size*4*2);
        k = ("%x" % random.getrandbits(size*4*8)).zfill(size*4*2);
      
        #Generate Public Key
        client.calculatePublicKey(d);
        qx = client.getBigNum(client.payload, client.getNumSize()*4*0);
        qy = client.getBigNum(client.payload, client.getNumSize()*4*1);
        
        #Generate Shared Secret
        client.multiply(b, qx, qy);
        bx = client.getBigNum(client.payload, client.getNumSize()*4*0);
        by = client.getBigNum(client.payload, client.getNumSize()*4*1);
      
        #Generate Signature
        client.setPrivateKey(d);
        client.setEphemeralKey(k);
        client.uploadData(len(binascii.a2b_hex(msg)), binascii.a2b_hex(msg));
        client.calculateSignature(len(binascii.a2b_hex(msg)));
        r = client.getBigNum(client.payload, client.getNumSize()*4*0);
        s = client.getBigNum(client.payload, client.getNumSize()*4*1);
              
        #Output TestCase
        dst.write("Msg = %s\n" % msg);
        dst.write("d = %s\n" % d);
        dst.write("b = %s\n" % b);
        dst.write("k = %s\n" % k);
        dst.write("Qx = %s\n" % qx);
        dst.write("Qy = %s\n" % qy);
        dst.write("Bx = %s\n" % bx);
        dst.write("By = %s\n" % by);
        dst.write("R = %s\n" % r);
        dst.write("S = %s\n" % s);
        dst.write("Result = P\n\n");
    return 0;

if __name__ == "__main__":
  app = EccApplication();
  sys.exit(app.main());