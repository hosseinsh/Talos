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

import json;

class MeasurementWriter:
  """Collect aggregate and saves Measurements"""
  file          = None;
  data          = {};
    
  def __init__(self, filename):
    if filename is not None:
      self.file = open(filename, "w");

  def add(self, test_name, measurement):
    if test_name not in self.data:
      self.data[test_name] = {};
    for key, value in measurement.iteritems():
      if key not in self.data[test_name]:
        self.data[test_name][key] = [];
      self.data[test_name][key].append(value);
    
  def save(self):
    if self.file is not None:
      json.dump(self.data, self.file, sort_keys=True); #indent=2
      self.file.close();
    self.file = None;