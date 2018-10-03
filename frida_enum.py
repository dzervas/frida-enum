# -*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function
import json

try:
    from pygments import highlight
    from pygments.lexers import JsonLexer
    from pygments.formatters import TerminalFormatter
except ImportError:
    PYGMENTS = False
else:
    PYGMENTS = True

from frida_wrap import FridaWrap


wrap = FridaWrap()

# Native
wrap.parser.add_argument("-m", "--module", help="select MODULE",
        action="store", type=str)
wrap.parser.add_argument("-a", "--modules", help="enumerate MODULES",
        action="store_const", const="modules", dest="action")
wrap.parser.add_argument("-e", "--module-exports", help="enumerate EXPORTS",
        action="store_const", const="module_exports", dest="action")
wrap.parser.add_argument("-i", "--module-imports", help="enumerate IMPORTS",
        action="store_const", const="module_imports", dest="action")
wrap.parser.add_argument("-s", "--module-symbols", help="enumerate SYMBOLS",
        action="store_const", const="module_symbols", dest="action")
# wrap.parser.add_argument("-r", "--ranges", help="enumerate RANGES",
        # action="store_const", const="ranges", dest="action")
# wrap.parser.add_argument("--malloc-ranges", help="enumerate malloc() RANGES",
        # action="store_const", const="malloc_ranges", dest="action")
wrap.parser.add_argument("-t", "--threads", help="enumerate THREADS",
        action="store_const", const="threads", dest="action")

# Kernel
wrap.parser.add_argument("--kernel-modules", help="enumerate KERNEL MODULES",
        action="store_const", const="kernel_modules", dest="action")
# wrap.parser.add_argument("--kernel-ranges", help="enumerate KERNEL RANGES",
        # action="store_const", const="kernel_ranges", dest="action")
# wrap.parser.add_argument("--kernel-malloc-ranges", help="enumerate KERNEL malloc() RANGES",
        # action="store_const", const="kernel_malloc_ranges", dest="action")

# Java
wrap.parser.add_argument("-j", "--java-loaded-classes", help="enumerate Java LOADED CLASSES",
        action="store_const", const="java_loaded_classes", dest="action")
wrap.parser.add_argument("--java-class-loaders", help="enumerate Java CLASS LOADERS",
        action="store_const", const="java_class_loaders", dest="action")
wrap.parser.add_argument("--java-instances", help="enumerate Java OBJECT INSTANCES",
        action="store_const", const="java_instances", dest="action")

# ObjC
wrap.parser.add_argument("-o", "--objc-classes", help="enumerate ObjC CLASSES",
        action="store_const", const="objc_classes", dest="action")
wrap.parser.add_argument("--objc-instances", help="enumerate ObjC INSTANCES",
        action="store_const", const="objc_instances", dest="action")
wrap.parser.add_argument("--objc-protocols", help="enumerate ObjC PROTOCOLS",
        action="store_const", const="objc_protocols", dest="action")

wrap.load_file_script("frida_enum.js")

if wrap.args.action is None:
    wrap.parser.print_help()
    exit(1)

fn = getattr(wrap.script.exports, wrap.args.action)
res = fn(wrap.args.module)
json_str = json.dumps(res, indent=4, sort_keys=True)

if PYGMENTS:
    print(highlight(json_str, JsonLexer(), TerminalFormatter()))
else:
    print(json_str)
