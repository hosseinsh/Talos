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

from TestInterface import TestInterface

class AppTimer(TestInterface):
  """Interface to Timer Application"""

  #Enums copied from test-interface.h
  CLEAR                   =  1
  GET_COUNT               =  2
  GET_VALUES              =  3
  SWITCH_TIMER_OUTPUT     =  4
  
  def enableTimerOutput(self):
    self.executeCommand(self.APP_TIMER, self.SWITCH_TIMER_OUTPUT, 1, [0x01]);

  def disableTimerOutput(self):
    self.executeCommand(self.APP_TIMER, self.SWITCH_TIMER_OUTPUT, 1, [0x00]);
  
  def clearTimer(self):
    """Clears all time Measurements"""
    self.executeCommand(self.APP_TIMER, self.CLEAR);
    
  def readMultiValueMeasurements(self):
    """Returns a Dictionary Key: Measurement[] (Key to Multiple Values)"""
    self.executeCommand(self.APP_TIMER, self.GET_COUNT);
    if self.payload_length != 1:
      raise IOError("payload_length != 1");
    count       = ord(self.payload[0]);
    measurements = {};
    self.executeCommand(self.APP_TIMER, self.GET_VALUES);
    
    if self.payload_length != count*8:
      raise IOError("failed to upload values");
    for i in range(0, count):
      key   = self.getLong(self.payload, 8*i+0);
      value = self.getLong(self.payload, 8*i+4);
      if key not in measurements: 
        measurements[key] = [];
      measurements[key].append(value);
    return measurements;

  def readMeasurementsAndSum(self):
    """Returns the sum of all measurements with same ID"""
    measurements = {};
    mmv = self.readMultiValueMeasurements();
    for key, mv in mmv.iteritems():
      if key not in measurements: 
        measurements[key] = 0;
      for value in mv:
        measurements[key] = measurements[key] + value;
    return measurements;
  
  def readMeasurements(self):
    """Returns a single measurements per ID"""
    measurements = {};
    mmv = self.readMultiValueMeasurements();
    for key, mv in mmv.iteritems():
      for value in mv:
        measurements[key] = value;
    return measurements;
