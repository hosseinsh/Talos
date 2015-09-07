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

class AppPailler(AppTimer):
  """Interface to Pailler Application"""
  
  #Enums copied from test-interface.h
  PAILLER_SET_P           =  1
  PAILLER_SET_Q           =  2
  PAILLER_SET_PLAINT      =  3
  PAILLER_GET_PLAINT      =  4
  PAILLER_SET_CIPHERT     =  5
  PAILLER_GET_CIPHERT     =  6
  PAILLER_GEN             =  7
  PAILLER_ENC             =  8
  PAILLER_DEC             =  9
  PAILLER_ADD             = 10
    
  def switchToHardwareCrypto(self):
    self.executeCommand(self.APP_MANAGEMENT, self.SWITCH_PKA, 1, [0x01]);

  def setKey(self, p, q):
    self.executeCommand(self.APP_PAILLER, self.PAILLER_SET_P, len(p), p);
    self.executeCommand(self.APP_PAILLER, self.PAILLER_SET_Q, len(q), q);

  def setPlainText(self, plaintext):
    self.executeCommand(self.APP_PAILLER, self.PAILLER_SET_PLAINT, len(plaintext), plaintext);
    
  def getPlainText(self):
    self.executeCommand(self.APP_PAILLER, self.PAILLER_GET_PLAINT, 0, []);
    return self.payload

  def setCipherText(self, ciphertext):
    self.executeCommand(self.APP_PAILLER, self.PAILLER_SET_CIPHERT, len(ciphertext), ciphertext);
    
  def getCipherText(self):
    self.executeCommand(self.APP_PAILLER, self.PAILLER_GET_CIPHERT, 0, []);
    return self.payload

  def generate(self):
    self.executeCommand(self.APP_PAILLER, self.PAILLER_GEN, 0, []);
  
  def encrypt(self):
    self.executeCommand(self.APP_PAILLER, self.PAILLER_ENC, 0, []);
    
  def decrypt(self):
    self.executeCommand(self.APP_PAILLER, self.PAILLER_DEC, 0, []);

  def add(self):
    self.executeCommand(self.APP_PAILLER, self.PAILLER_ADD, 0, []);
    