#!/usr/bin/env python
"""Enforce certain properties on C/C++ code bases"""

import argparse
import logging
import os.path
import re

import clang.cindex

logger = logging.getLogger(__name__)


def is_local_decl_kind(node_kind):
    return (
        node_kind.is_declaration() and
        node_kind == clang.cindex.CursorKind.VAR_DECL and
        node_kind == clang.cindex.CursorKind.PARM_DECL and
        node_kind == clang.cindex.CursorKind.FIELD_DECL
    )


def is_name_decl_kind(node_kind):
    return (
        node_kind == clang.cindex.CursorKind.STRUCT_DECL or
        node_kind == clang.cindex.CursorKind.UNION_DECL or
        node_kind == clang.cindex.CursorKind.CLASS_DECL or
        node_kind == clang.cindex.CursorKind.ENUM_DECL or
        node_kind == clang.cindex.CursorKind.ENUM_CONSTANT_DECL
    )


def find_globals(node, all_global_decls):
    if node.kind.is_declaration():
        if not is_local_decl_kind(node.kind):
            if "" == node.spelling:
                # ignore anonymous declarations
                return

            is_proper_name = re.match(r"[A-Z]", '%s' % node.spelling)

            if is_name_decl_kind(node.kind) and not is_proper_name:
                print '%s needs to start with a capital' % node.spelling

            if not is_name_decl_kind(node.kind) and is_proper_name:
                print '%s needs to start with lower case' % node.spelling

            all_global_decls.append(node.spelling)

    if node.kind == clang.cindex.CursorKind.INCLUSION_DIRECTIVE:
        return

    for n in node.get_children():
        find_globals(n, all_global_decls)


def check_locals(node, all_global_decls):
    if is_local_decl_kind(node.kind):
        if node.spelling in all_global_decls:
            print '%s is duplicated' % node.spelling

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

    index = clang.cindex.Index.create()

    all_files = []
    for directory in args.directory:
        logger.info("inspecting %s" % directory)
        for (root, dirs, files) in os.walk(directory):
            for f in files:
                if f.endswith(".h") or f.endswith(".c"):
                    all_files.append(os.path.join(root, f))

    all_global_decls = []

    for fn in all_files:
        logger.info("parsing %s" % fn)
        translation_unit = index.parse(fn)
        logger.info("translation unit %s" % translation_unit.spelling)

        find_globals(translation_unit.cursor, all_global_decls)

    all_global_decls = frozenset(all_global_decls)

    for fn in all_files:
        logger.info("parsing %s" % fn)
        translation_unit = index.parse(fn)
        logger.info("translation unit %s" % translation_unit.spelling)

        check_locals(translation_unit.cursor, all_global_decls)
