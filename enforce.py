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
        (
            node_kind == clang.cindex.CursorKind.VAR_DECL or
            node_kind == clang.cindex.CursorKind.PARM_DECL or
            node_kind == clang.cindex.CursorKind.FIELD_DECL
        )
    )


def is_name_decl_kind(node_kind):
    return (
        node_kind == clang.cindex.CursorKind.STRUCT_DECL or
        node_kind == clang.cindex.CursorKind.UNION_DECL or
        node_kind == clang.cindex.CursorKind.CLASS_DECL or
        node_kind == clang.cindex.CursorKind.ENUM_DECL or
        node_kind == clang.cindex.CursorKind.ENUM_CONSTANT_DECL
    )


def node_error_msg(node):
    return '%s:%d: Error with symbol %s' % (node.location.file, node.location.line, node.spelling)


def find_and_check_globals(node, all_global_decls, reject_node_predicate, output):
    """
    node a clang cursor
    reject_node_predicate(node)
    output(level, msg)
    """

    if reject_node_predicate(node):
        return

    if node.kind.is_declaration():
        if not is_local_decl_kind(node.kind):
            if "" == node.spelling:
                # ignore anonymous declarations
                return

            is_proper_name = re.match(r"[A-Z]", '%s' % node.spelling)

            if is_name_decl_kind(node.kind) and not is_proper_name:
                output(1, '%s should to start with a capital' %
                       node_error_msg(node))

            if not is_name_decl_kind(node.kind) and is_proper_name:
                output(1, '%s should start with lower case' %
                       node_error_msg(node))

            if (node.spelling in all_global_decls
                    and node.kind != all_global_decls[node.spelling]):
                output(0, '%s should not appear multiple times (kind: %s, other kind: %s)' % (
                    node_error_msg(node),
                    node.kind,
                    all_global_decls[node.spelling]
                ))

            all_global_decls[node.spelling] = node.kind

    if node.kind == clang.cindex.CursorKind.INCLUSION_DIRECTIVE:
        return

    for n in node.get_children():
        find_and_check_globals(
            n, all_global_decls, reject_node_predicate, output)


def check_locals(node, all_global_decls, reject_node_predicate, output):
    """
    node a clang cursor
    reject_node_predicate(node)
    output(level, msg)
    """

    if reject_node_predicate(node):
        return

    if is_local_decl_kind(node.kind):
        if node.spelling in all_global_decls:
            output(0, '%s is also a global symbol (kind: %s, other kind: %s)' % (
                node_error_msg(node),
                node.kind,
                all_global_decls[node.spelling]
            ))

if __name__ == "__main__":
    logging.basicConfig()

    def directory(p):
        assert os.path.isdir(p), "path must be a directory"
        return os.path.normpath(p)

    parser = argparse.ArgumentParser(description="Check a codebase")
    parser.add_argument('directory', type=directory, nargs='+')
    parser.add_argument('--verbose', dest='is_verbose', action='store_true')
    parser.add_argument('--level', dest='max_level', type=int, default=0)
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

    all_global_decls = {}

    def reject_nodes_outside(node):
        if node.kind == clang.cindex.CursorKind.TRANSLATION_UNIT:
            return False

        return (
            not node.location.file or
            not any(
                os.path.abspath(node.location.file.name).startswith(
                    os.path.abspath(root))
                for root in args.directory
            )
        )

    def output(level, msg):
        if level <= args.max_level:
            print msg

    for fn in all_files:
        logger.info("parsing %s" % fn)
        translation_unit = index.parse(fn)
        logger.info("translation unit %s" % translation_unit.spelling)

        find_and_check_globals(
            translation_unit.cursor, all_global_decls, reject_nodes_outside, output)

    all_global_decls = frozenset(all_global_decls)

    for fn in all_files:
        logger.info("parsing %s" % fn)
        translation_unit = index.parse(fn)
        logger.info("translation unit %s" % translation_unit.spelling)

        check_locals(translation_unit.cursor,
                     all_global_decls, reject_nodes_outside, output)
