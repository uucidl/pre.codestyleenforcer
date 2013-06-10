#!/usr/bin/env python
"""Enforce certain properties on C/C++ code bases"""

import argparse
import os.path
import logging

import clang.cindex

logger = logging.getLogger(__name__)

if __name__ == "__main__":
    logging.basicConfig()

    def directory(p):
        assert os.path.isdir(p), "path must be a directory"
        return os.path.normpath(p)

    parser = argparse.ArgumentParser(description="Check a codebase")
    parser.add_argument('directory', type=directory, nargs='+')
    parser.add_argument('--verbose', dest='is_verbose', action='store_true')

    args = parser.parse_args()

    if args.is_verbose:
        logger.setLevel(logging.INFO)

    for directory in args.directory:
        logger.info("inspecting %s" % directory)
        assert False, "doing nothing for now"
