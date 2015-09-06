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

import json, numpy;

class MeasurementReader(object):
  """Load Measurements and perform statistical analysis"""
  data = {};

  def loadAndSum(self, file_name, algorithm_name):
    handle = open(file_name, 'r');
    data_import = json.load(handle);
    handle.close();

    #Iterate tests
    for test_name, test_data in data_import.iteritems():
      if test_name not in self.data:
        self.data[test_name] = {};
      if algorithm_name not in self.data[test_name]:
        self.data[test_name][algorithm_name] = [];        
        
      #Sum up the measurements
      for measurements in test_data.values():
        for x in range(0, len(measurements)):
          while len(self.data[test_name][algorithm_name]) < len(measurements):
            self.data[test_name][algorithm_name].append(0);
          self.data[test_name][algorithm_name][x] = self.data[test_name][algorithm_name][x] + measurements[x];
  
  def loadAndAggregate(self, file_name, algorithm_name):
    handle = open(file_name, 'r');
    data_import = json.load(handle);
    handle.close();

    #Iterate tests
    for test_name, test_data in data_import.iteritems():
      keysize, phase = test_name.split("-");
      column_name = algorithm_name + "-" + phase
      test_name = keysize;
      if test_name not in self.data:
        self.data[test_name] = {};
      if column_name not in self.data[test_name]:
        self.data[test_name][column_name] = [];        
        
      #Sum up the measurements
      for measurements in test_data.values():
        for x in range(0, len(measurements)):
          self.data[test_name][column_name].append(measurements[x]);
  
  def plot(self, output, scale_x=1, scale_y=1, scale_std=1):
    #Print Header
    output.write("#");
    for test_name, algorithms in self.data.iteritems():
      for key in iter(sorted(algorithms.keys())):
        output.write("%s " % key);
        output.write("%s-std-dev " % key);
      output.write("\n");
      break;
    
    #Print Data
    for test_name, algorithms in iter(sorted(self.data.iteritems())):
      output.write("%d " % (int(test_name)*float(scale_x)));
      for key, measurements in iter(sorted(algorithms.iteritems())):
        output.write("%f " % (numpy.average(measurements)*float(scale_y)));
        output.write("%f " % (numpy.std(measurements, ddof=1)*float(scale_std)));
      output.write("i\n");
