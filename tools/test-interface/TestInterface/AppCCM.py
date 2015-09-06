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

class AppCCM(AppTimer):
  """Interface to CCM Application"""
  
  #Enums copied from test-interface.h
  SELECT_CCM_ENGINE       =  1;
  SWITCH_UPLOAD           =  2;
  CCM_SET_KEY             =  4;
  CCM_ENCRYPT             =  5;
  CCM_DECRYPT             =  6;
  
  def switchToHardwareCrypto(self):
    self.executeCommand(self.APP_MANAGEMENT, self.SWITCH_CRYPTO, 1, [0x01]);
    self.executeCommand(self.APP_CCM, self.SELECT_CCM_ENGINE, 1, [0x00]);

  def switchToSoftwareCrypto(self):
    self.executeCommand(self.APP_MANAGEMENT, self.SWITCH_CRYPTO, 1, [0x00]);
    self.executeCommand(self.APP_CCM, self.SELECT_CCM_ENGINE, 1, [0x01]);

  def enableUpload(self):
    self.executeCommand(self.APP_MANAGEMENT, self.SWITCH_UPLOAD, 1, [0x01]);

  def disableUpload(self):
    self.executeCommand(self.APP_MANAGEMENT, self.SWITCH_UPLOAD, 1, [0x00]);
    
  def setKey(self, key):
    self.executeCommand(self.APP_CCM, self.CCM_SET_KEY, len(key), key);

  def uploadMessage(self, msg, nonce, aal):
    space = " " * 16;
    pad   = " " * (16-len(nonce));
    self.uploadData(len(msg) + 32 + len(aal), msg+space+nonce+pad+aal);

  def encrypt(self, mac_len, msg_len, len_len, add_len):
    payload = [0]*8;
    self.setShort(payload, 0, mac_len);
    self.setShort(payload, 4, len_len);
    self.setShort(payload, 2, msg_len);
    self.setShort(payload, 6, add_len);
    self.executeCommand(self.APP_CCM, self.CCM_ENCRYPT, len(payload), payload);

  def decrypt(self, mac_len, msg_len, len_len, add_len):
    payload = [0]*8;
    self.setShort(payload, 0, mac_len);
    self.setShort(payload, 4, len_len);
    self.setShort(payload, 2, msg_len);
    self.setShort(payload, 6, add_len);
    self.executeCommand(self.APP_CCM, self.CCM_DECRYPT, len(payload), payload);
