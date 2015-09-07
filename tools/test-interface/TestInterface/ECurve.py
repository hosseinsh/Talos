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

class ECurve(AppTimer):
  """Functions and Constants used for Prime Elliptic Curves"""
  
  curve = None;
  
  #Curve Info
  CURVE_INFO = {
    "[P-192]": {
    "size" : 6,
    "prime": "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF",
    "A"    : "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC",
    "B"    : "64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1",
    "N"    : "FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831",
    "Gx"   : "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",
    "Gy"   : "07192B95FFC8DA78631011ED6B24CDD573F977A11E794811",
  },
    "[P-224]": {
    "size" : 7,
    "prime": "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001",
    "A"    : "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE",
    "B"    : "B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4",
    "N"    : "FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D",
    "Gx"   : "B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21",
    "Gy"   : "BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34",
  },
    "[P-256]": {
    "size" : 8,
    "prime": "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
    "A"    : "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
    "B"    : "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
    "N"    : "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
    "Gx"   : "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
    "Gy"   : "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
  },
    "[P-384]": {
    "size" : 12,
    "prime": "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
    "A"    : "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC",
    "B"    : "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",
    "N"    : "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",
    "Gx"   : "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
    "Gy"   : "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
  }}

  #Copy CurveInfo into Curve/Hash tuples
  CURVE_INFO["[P-192,SHA-256]"] = CURVE_INFO["[P-192]"];
  CURVE_INFO["[P-224,SHA-256]"] = CURVE_INFO["[P-224]"];
  CURVE_INFO["[P-256,SHA-256]"] = CURVE_INFO["[P-256]"];
  CURVE_INFO["[P-384,SHA-256]"] = CURVE_INFO["[P-384]"];

  def getNumSize(self):
    return self.curve["size"];
  
  def setBigNum(self, payload, index, value):
    for x in range(len(value), 0, -8):
      self.setLong(payload, index+(len(value)-x)/2, int(value[x-8:x], 16));
      
  def getBigNum(self, payload, index):
    number = "";
    for x in range(self.getNumSize()*4, 0, -4):
      number = number + "%0.8x" % (self.getLong(payload, index+x-4));
    return number;
 
  def setCurve(self, curve_name):
    self.curve = self.CURVE_INFO[curve_name];
    payload = [0]*(4 + 4*6* self.getNumSize());
    self.setLong(payload, 0, self.getNumSize());
    self.setBigNum(payload, 4 + 0*self.getNumSize()*4, self.curve["prime"]);
    self.setBigNum(payload, 4 + 1*self.getNumSize()*4, self.curve["N"]);
    self.setBigNum(payload, 4 + 2*self.getNumSize()*4, self.curve["A"]);
    self.setBigNum(payload, 4 + 3*self.getNumSize()*4, self.curve["B"]);
    self.setBigNum(payload, 4 + 4*self.getNumSize()*4, self.curve["Gx"]);
    self.setBigNum(payload, 4 + 5*self.getNumSize()*4, self.curve["Gy"]);
    return payload;
