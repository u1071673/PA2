#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: John Young
# Date:   3-19-2019
# Course: CS 4480, University of Utah, School of Computing
# Copyright: CS 4480 and John Young - This work may not be copied for use in Academic Coursework.
#
# I, John Young, certify that I wrote this code from scratch and did not copy it in part or whole from
# another source.  Any references used in the completion of the assignment are cited in my README file.
#
# File Contents
#
#    This File is by [Debug SDN Ryu controller with Pycharm](http://installfights.blogspot.com/2016/10/debug-sdn-ryu-controller-with-pycharm.html?m=1)

import sys
import config
from ryu.cmd import manager

def main():
    # Add arguments (except -v) to the ryu app.
    if '-v' in sys.argv:
        config.verbose = True
        sys.argv.remove('-v')

    if len(sys.argv) <= 1: # If empty
        sys.argv += config.def_sys_args

    manager.main()

if __name__ == '__main__':
    main()
