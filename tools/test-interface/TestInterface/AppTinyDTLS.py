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

from AppTimer import AppTimer

class AppTinyDTLS(AppTimer):
  """Interface to TinyDTLS Client"""
  
  #Enums copied from dtls-client.c
  SELECT_ENGINE    = 1;
  SELECT_AUTH_TYPE = 2;
  CONNECT          = 3;
  START_RPL_ROOT   = 4;
  
  def switchToHardwareCrypto(self):
    self.executeCommand(self.APP_TINYDTLS, self.SELECT_ENGINE, 1, [0x01]);

  def switchToSoftwareCrypto(self):
    self.executeCommand(self.APP_TINYDTLS, self.SELECT_ENGINE, 1, [0x00]);
    
  def switchToPSK(self):
    self.executeCommand(self.APP_TINYDTLS, self.SELECT_AUTH_TYPE, 1, [0x01]);

  def switchToRAW(self):
    self.executeCommand(self.APP_TINYDTLS, self.SELECT_AUTH_TYPE, 1, [0x02]);

  def switchToX509(self):
    self.executeCommand(self.APP_TINYDTLS, self.SELECT_AUTH_TYPE, 1, [0x03]);

  def performDTLSHandshake(self, ipv6_address):
    self.executeCommand(self.APP_TINYDTLS, self.CONNECT, len(ipv6_address), ipv6_address);
