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

import sys, os, binascii, abc

from argparse import ArgumentParser
from argparse import RawDescriptionHelpFormatter

class TerminalApplication(object):
  __metaclass__ = abc.ABCMeta;

  def __init__(self):
    self.program_name = os.path.basename(sys.argv[0]);

  @abc.abstractmethod
  def define_arguments(self, parser):
    """This Methode should add application specific arguments to parser""";
    return;

  @abc.abstractmethod
  def instantiate_interface(self, args):
    """This Methode should instantiate a subclass of TestInterface""";
    return;

  @abc.abstractmethod
  def execute_test(self, client, args):
    """This Methode should contain the main code""";
    return;

  def main(self):
    try:
      # Setup argument parser
      parser = ArgumentParser(formatter_class=RawDescriptionHelpFormatter);
      parser.add_argument("-a", "--ip-address",dest="ip",      metavar="a",          help="TCP/IP Address to use instead of serial port");
      parser.add_argument("-p", "--port",      dest="port",    metavar="p",          help="TCP Port to use in conjunction with address");    
      parser.add_argument("-d", "--no-reset",  dest="reset",   action="store_false", help="don't reset target");
      parser.add_argument("-r", "--relic",     dest="engine",  action="store_true",  help="use relics implementation (default: hw)");
      parser.add_argument("-e", "--export",    dest="export",  action="store_true",  help="enable timer output on GPIOs");

      # Call into subclass for additional arguments
      self.define_arguments(parser);

      #Process arguments
      args = parser.parse_args();

      # Call into subclass to obtain test interface
      # TODO Rewrite test interface to make this hack obsolete
      client = self.instantiate_interface(args);

      #Connect to Target
      if args.ip is not None:
        client.connect(args.ip, int(args.port));
      else:
        client.open();

      #Reset Target
      if args.reset:
        client.reset();
        client.readResponse();

      #Switch on HardwareCrypto
      if args.engine:
        try:
          client.switchToSoftwareCrypto();
        except AttributeError:
          sys.stderr.write("Software crypto not available!\n");
      else:
        try:
          client.switchToHardwareCrypto();
        except AttributeError:
          sys.stderr.write("Hardware crypto not available!\n");

      #Enable Timer output on GPIOs  
      if args.export:
        client.enableTimerOutput();

      # Call into subclass to execute test and return result ocde
      return self.execute_test(client, args);

    #Handle keyboard interrupt
    except KeyboardInterrupt:
      return 1;

    #Handle keyboard exceptions
    #except Exception, e:
    #  indent = len(self.program_name) * " ";
    #  sys.stderr.write(self.program_name + ": " + repr(e) + "\n");
    #  sys.stderr.write(indent + "  for help use --help\n");
    #  return 2;
