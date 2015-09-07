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
from TestInterface.AppCCM import AppCCM

class CcmApplication(TerminalApplication):
  def define_arguments(self, parser):
    parser.add_argument(dest="min",  help="min in bytes",);
    parser.add_argument(dest="max",  help="max in bytes",);
    parser.add_argument(dest="step", help="step in bytes",);
    parser.add_argument(dest="enc",  help="file to save encryption test data to");
    parser.add_argument(dest="dec",  help="file to save decryption test data to");

  def instantiate_interface(self, args):
    return AppCCM();

  def execute_test(self, client, args):
    #Open destinations
    enc = open(args.enc, "w");
    dec = open(args.dec, "w");
    
    #Write Header
    enc.write("Plen = 24\nNlen = 13\nTlen = 8\n\n[Alen = 0]\n\n");
    dec.write("[Alen = 0, Plen = 24, Nlen = 13, Tlen = 8]\n\n");
    
    #Generate test data
    random.seed();
    key    = ("%x" % random.getrandbits(16*8)).zfill(16*2);
    nonce  = ("%x" % random.getrandbits(13*8)).zfill(13*2);

    
    enc.write("Key = %s\n" % key);
    dec.write("Key = %s\n\n" % key);
    enc.write("Nonce = %s\n\n" % nonce);
    dec.write("Nonce = %s\n\n" % nonce);

    for i in range(int(args.min), int(args.max)+1, int(args.step)):
      payload = ("%x" % random.getrandbits(i*8)).zfill(i*2);
      
      client.setKey(binascii.a2b_hex(key))
      client.uploadMessage(binascii.a2b_hex(payload), binascii.a2b_hex(nonce), binascii.a2b_hex("00"));
      client.encrypt(8, 15-13, i, 0)
      
      ct_length = client.getLong(client.payload, 0);
      ct = binascii.b2a_hex(client.downloadData(ct_length));

      enc.write("Count = %i\n" % i);
      dec.write("Count = %i\n" % i);
      enc.write("Plen = %i\n" % i);
      dec.write("Plen = %i\n" % i);
      enc.write("Adata = 00\n");
      dec.write("Adata = 00\n");
     
      dec.write("Result = Pass\n");
      enc.write("Payload = %s\n"  % payload);
      dec.write("Payload = %s\n"  % payload);
      enc.write("CT = %s\n\n"  % ct);
      dec.write("CT = %s\n\n"  % ct);
      
    return 0;

if __name__ == "__main__":
  app = CcmApplication();
  sys.exit(app.main());
