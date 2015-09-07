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

class CavsReader:
  """Parses CAVS response file and presents the data in an iterable form"""
  file     = None;
  section  = ""
  elements = None;
  entry    = "";
  peek     = 0;
    
  def __init__(self, filename, section, elements):
    self.file = open(filename);
    self.elements = elements;
    self.section = section
    
  def selectSection(self, section):
    self.section = section;

  def enablePeekOne(self):
    self.peek = 1;
  
  def seek(self):
    self.entry = {};
    self.file.seek(0);
    for line in self.file:
      if line.strip(" \n\r") == self.section:
        return;
      key, value = line.partition("=")[::2]
      self.entry[key.strip()] = value.strip(" \n");
    raise RuntimeError("Section not found");

  def __iter__(self):
    self.seek();
    return self;
  
  def next(self):
    count = 0;
    line = self.file.next();
    while count != len(self.elements):
      if line[0:1] == "[":
        raise StopIteration
      key, value = line.partition("=")[::2]
      self.entry[key.strip()] = value.strip(" \n");
      if(key.strip() in self.elements):
        count = count + 1;
      line = self.file.next();
      
    if self.peek:
      key, value = line.partition("=")[::2]
      self.entry[key.strip()] = value.strip(" \n");
           
    return self.entry;
