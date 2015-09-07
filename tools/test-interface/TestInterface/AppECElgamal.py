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

from ECurve import ECurve

class AppECElgamal(ECurve):
  """Interface to EC-Elgamal Application"""
  
  #Enums copied from test-interface.h
  EG_SET_CURVE            =  1
  EG_SET_EXPONENT         =  2
  EG_SET_PLAIN_TEXT       =  3
  EG_GET_PLAIN_TEXT       =  4
  EG_GENERATE             =  5
  EG_MAP_TO_EC            =  6
  EG_MAP_FROM_EC          =  7
  EG_ENC                  =  8
  EG_DEC                  =  9
  EG_ADD                  = 10
  EG_MAP_TO_EC_ALT        = 11
    
  def switchToHardwareCrypto(self):
    self.executeCommand(self.APP_MANAGEMENT, self.SWITCH_PKA, 1, [0x01]);
    
  def selectCurve(self, curve_name):
    payload = self.setCurve(curve_name);
    self.executeCommand(self.APP_ELGAMAL, self.EG_SET_CURVE, len(payload), payload);

  def setExponent(self, exponent):
    payload = [0]*(4 * self.getNumSize());
    self.setBigNum(payload, 0, exponent);
    self.executeCommand(self.APP_ELGAMAL, self.EG_SET_EXPONENT, len(payload), payload);

  def setPlainText(self, plaintext):
    payload = [0]*(4 * self.getNumSize());
    self.setBigNum(payload, 0, plaintext);
    self.executeCommand(self.APP_ELGAMAL, self.EG_SET_PLAIN_TEXT, len(payload), payload);
    
  def getPlainText(self):
    self.executeCommand(self.APP_ELGAMAL, self.EG_GET_PLAIN_TEXT, 0, []);
    return self.payload

  def mapToEC(self):
    self.executeCommand(self.APP_ELGAMAL, self.EG_MAP_TO_EC, 1, [0x10]);    
    return self.payload

  def mapToECAlternative(self):
    self.executeCommand(self.APP_ELGAMAL, self.EG_MAP_TO_EC_ALT);    
    
  def mapFromEC(self):
    self.executeCommand(self.APP_ELGAMAL, self.EG_MAP_FROM_EC, 1, [0x10]);

  def generate(self):
    self.executeCommand(self.APP_ELGAMAL, self.EG_GENERATE, 0, []);
  
  def encrypt(self):
    self.executeCommand(self.APP_ELGAMAL, self.EG_ENC, 0, []);
    
  def decrypt(self):
    self.executeCommand(self.APP_ELGAMAL, self.EG_DEC, 0, []);

  def add(self):
    self.executeCommand(self.APP_ELGAMAL, self.EG_ADD, 0, []);
    