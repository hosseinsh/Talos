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

class AppECC(ECurve):
  """Interface to ECC Application"""
  
  #Enums copied from test-interface.h
  SELECT_ECC_ENGINE       =  1
  EC_SET_CURVE            =  2
  EC_SET_GENERATOR        =  3
  EC_SET_PRIVATE_KEY      =  4
  EC_SET_PUBLIC_KEY       =  5
  EC_SET_EPHEMERAL_KEY    =  6
  EC_MULTIPLY             =  7
  EC_SIGN                 =  8
  EC_VERIFY               =  9
  EC_GENERATE             = 10
  SWITCH_SIM_MUL          = 11
  
  def switchToHardwareCrypto(self):
    #We need CryptoEngine for Sign/Verify
    self.executeCommand(self.APP_MANAGEMENT, self.SWITCH_CRYPTO, 1, [0x01]);
    self.executeCommand(self.APP_MANAGEMENT, self.SWITCH_PKA, 1, [0x01]);
    self.executeCommand(self.APP_ECC, self.SELECT_ECC_ENGINE, 1, [0x00]);

  def switchToSoftwareCrypto(self):
    self.executeCommand(self.APP_MANAGEMENT, self.SWITCH_PKA, 1, [0x00]);
    self.executeCommand(self.APP_ECC, self.SELECT_ECC_ENGINE, 1, [0x01]);

  def enableSimMul(self):
    self.executeCommand(self.APP_ECC, self.SWITCH_SIM_MUL, 1, [0x01]);

  def disableSimMul(self):
    self.executeCommand(self.APP_ECC, self.SWITCH_SIM_MUL, 1, [0x00]);

  def selectCurve(self, curve_name):
    payload = self.setCurve(curve_name);
    self.executeCommand(self.APP_ECC, self.EC_SET_CURVE, len(payload), payload);

  def setGenerator(self, Qx, Qy):
    payload = [0]*(4*2* self.getNumSize());
    self.setBigNum(payload, 0*self.getNumSize()*4, Qx);
    self.setBigNum(payload, 1*self.getNumSize()*4, Qy);
    self.executeCommand(self.APP_ECC, self.EC_SET_GENERATOR, len(payload), payload);

  def setPrivateKey(self, d):
    payload = [0]*(4* self.getNumSize());
    self.setBigNum(payload, 0, d);
    self.executeCommand(self.APP_ECC, self.EC_SET_PRIVATE_KEY, len(payload), payload);
  
  def setPublicKey(self, Qx, Qy):
    payload = [0]*(4*2* self.getNumSize());
    self.setBigNum(payload, 0*self.getNumSize()*4, Qx);
    self.setBigNum(payload, 1*self.getNumSize()*4, Qy);
    self.executeCommand(self.APP_ECC, self.EC_SET_PUBLIC_KEY, len(payload), payload);
    
  def setEphemeralKey(self, d):
    payload = [0]*(4* self.getNumSize());
    self.setBigNum(payload, 0, d);
    self.executeCommand(self.APP_ECC, self.EC_SET_EPHEMERAL_KEY, len(payload), payload);

  def multiply(self, scalar, x, y):
    payload = [0]*(3 * 4 * self.getNumSize());
    self.setBigNum(payload, 0*self.getNumSize()*4, scalar);
    self.setBigNum(payload, 1*self.getNumSize()*4, x);
    self.setBigNum(payload, 2*self.getNumSize()*4, y);
    self.executeCommand(self.APP_ECC, self.EC_MULTIPLY, len(payload), payload);
    
  def calculatePublicKey(self, d):
    payload = [0]*(4 * self.getNumSize());
    self.setBigNum(payload, 0*self.getNumSize()*4, d);
    self.executeCommand(self.APP_ECC, self.EC_GENERATE, len(payload), payload);
  
  def calculateSignature(self, byte_count):
    payload = [0]*(4);
    self.setLong(payload, 0, byte_count);
    self.executeCommand(self.APP_ECC, self.EC_SIGN, len(payload), payload);
    
  def verifySignature(self, byte_count, R, S):
    payload = [0]*(4 + 4*2* self.getNumSize());
    self.setLong(payload, 0, byte_count);
    self.setBigNum(payload, 4 + 0*self.getNumSize()*4, R);
    self.setBigNum(payload, 4 + 1*self.getNumSize()*4, S);
    self.executeCommand(self.APP_ECC, self.EC_VERIFY, len(payload), payload);
