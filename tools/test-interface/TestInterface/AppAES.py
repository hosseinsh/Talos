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

class AppAES(AppTimer):
  """Interface to AES Application"""
  
  #Enums copied from test-interface.h
  SELECT_AES_MODE         =  1;
  AES_SWITCH_UPLOAD       =  2;
  AES_SET_KEY             =  4;
  AES_SET_IV              =  5;
  AES_GET_IV              =  6;
  AES_ENCRYPT             =  7;
  AES_DECRYPT             =  8;
  SELECT_AES_INTERFACE    =  9;
  CMC_ENCRYPT             = 10;
  CMC_DECRYPT             = 11;
  SELECT_AES_ENGINE       = 12;

  #Enums copied from aes.h
  AES_ECB                 =  1;
  AES_CBC                 =  2;
  AES_CTR                 =  3;
    
  def switchToHardwareCrypto(self):
    self.executeCommand(self.APP_MANAGEMENT, self.SWITCH_CRYPTO, 1, [0x01]);
    self.executeCommand(self.APP_AES, self.SELECT_AES_ENGINE, 1, [0x00]);

  def switchToSoftwareCrypto(self):
    self.executeCommand(self.APP_MANAGEMENT, self.SWITCH_CRYPTO, 1, [0x00]);
    self.executeCommand(self.APP_AES, self.SELECT_AES_ENGINE, 1, [0x01]);
    
  def switchToDMA(self):
    self.executeCommand(self.APP_AES, self.SELECT_AES_INTERFACE, 1, [0x00]);

  def switchToRegister(self):
    self.executeCommand(self.APP_AES, self.SELECT_AES_INTERFACE, 1, [0x01]);
  
  def switchToECBMode(self):
    self.executeCommand(self.APP_AES, self.SELECT_AES_MODE, 1, [self.AES_ECB]);

  def switchToCBCMode(self):
    self.executeCommand(self.APP_AES, self.SELECT_AES_MODE, 1, [self.AES_CBC]);

  def switchToCTRMode(self):
    self.executeCommand(self.APP_AES, self.SELECT_AES_MODE, 1, [self.AES_CTR]);

  def enableUpload(self):
    self.executeCommand(self.APP_MANAGEMENT, self.AES_SWITCH_UPLOAD, 1, [0x01]);

  def disableUpload(self):
    self.executeCommand(self.APP_MANAGEMENT, self.AES_SWITCH_UPLOAD, 1, [0x00]);

  def setKey(self, key):
    self.executeCommand(self.APP_AES, self.AES_SET_KEY, len(key), key);
    
  def setIV(self, iv):
    self.executeCommand(self.APP_AES, self.AES_SET_IV, len(iv), iv);
    
  def getIV(self):
    self.executeCommand(self.APP_AES, self.AES_GET_IV, 0, []);

  def uploadMessage(self, msg):
    self.uploadData(len(msg), msg);

  def encrypt(self, msg_len):
    payload = [0]*4;
    self.setLong(payload, 0, msg_len);
    self.executeCommand(self.APP_AES, self.AES_ENCRYPT, len(payload), payload);

  def decrypt(self, msg_len):
    payload = [0]*4;
    self.setLong(payload, 0, msg_len);
    self.executeCommand(self.APP_AES, self.AES_DECRYPT, len(payload), payload);
    
  def encrypt_cmc(self, msg_len):
    payload = [0]*4;
    self.setLong(payload, 0, msg_len);
    self.executeCommand(self.APP_AES, self.CMC_ENCRYPT, len(payload), payload);

  def decrypt_cmc(self, msg_len):
    payload = [0]*4;
    self.setLong(payload, 0, msg_len);
    self.executeCommand(self.APP_AES, self.CMC_DECRYPT, len(payload), payload);
