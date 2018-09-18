# -*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function
import frida
from frida_tools.application import ConsoleApplication

JS_CALLBACK_OBJ = """
rpc.exports = {
    // Native
    modules: function() {
        return Process.enumerateModulesSync();
    },

    module_imports: function(module) {
        return Module.enumerateImportsSync(module);
    },

    module_exports: function(module) {
        return Module.enumerateExportsSync(module);
    },

    module_symbols: function(module) {
        return Module.enumerateSymbolsSync(module);
    },

/*
    ranges: function() {
        return Process.enumerateThreadsSync();
    },

    malloc_ranges: function() {
        return Process.enumerateThreadsSync();
    },
*/
    threads: function() {
        return Process.enumerateThreadsSync();
    },

    // Kernel
    kernel_modules: function() {
        return Process.enumerateModulesSync();
    },

/*
    kernel_ranges: function() {
        return Process.enumerateThreadsSync();
    },

    kernel_malloc_ranges: function() {
        return Process.enumerateThreadsSync();
    },
*/

    // Java
    java_loaded_classes: function(filter) {
        Java.perform(function() {
            return Java.enumerateLoadedClassesSync()
        })
    },

    java_instances: function(className) {
        Java.perform(function() {
            return Java.chooseSync(className);
        });
    },

    // ObjC
    objc_classes: function() {
        return ObjC.classes;
    },

    objc_instances: function(module) {
        return ObjC.chooseSync(module);
    },

    objc_protocols: function(module) {
        return ObjC.protocols;
    },
}

"""


def script_deploy(session):
    def on_message(msg, data):
        print("[+] " + msg)

    script = session.create_script(name="enum", source=JS_CALLBACK_OBJ)
    script.on("message", on_message)
    script.load()
    return script


class EnumerApplication(ConsoleApplication):
    cmds = []

    def _usage(self):
        return "usage: %prog [options] target"

    def _add_options(self, parser):
        # Native
        parser.add_option("-m", "--module", help="enumerate MODULES",
                action="store", type="string")
        parser.add_option("-a", "--modules", help="enumerate MODULES",
                action="callback", callback=lambda a,b,c,d: self.cmds.append("modules"))
        parser.add_option("-e", "--module-exports", help="enumerate EXPORTS",
                action="callback", callback=lambda a,b,c,d: self.cmds.append("module_exports"))
        parser.add_option("-i", "--module-imports", help="enumerate IMPORTS",
                action="callback", callback=lambda  a,b,c,d: self.cmds.append("module_imports"))
        parser.add_option("-s", "--module-symbols", help="enumerate SYMBOLS",
                action="callback", callback=lambda  a,b,c,d: self.cmds.append("module_symbols"))
        # parser.add_option("-r", "--ranges", help="enumerate RANGES",
                # action="callback", callback=lambda a,b,c,d: self.cmds.append("ranges"))
        # parser.add_option("--malloc-ranges", help="enumerate malloc() RANGES",
                # action="callback", callback=lambda a,b,c,d: self.cmds.append("malloc_ranges"))
        parser.add_option("-t", "--threads", help="enumerate THREADS",
                action="callback", callback=lambda a,b,c,d: self.cmds.append("threads"))

        # Kernel
        parser.add_option("--kernel-modules", help="enumerate KERNEL MODULES",
                action="callback", callback=lambda a,b,c,d: self.cmds.append("kernel_modules"))
        # parser.add_option("--kernel-ranges", help="enumerate KERNEL RANGES",
                # action="callback", callback=lambda a,b,c,d: self.cmds.append("kernel_ranges"))
        # parser.add_option("--kernel-malloc-ranges", help="enumerate KERNEL malloc() RANGES",
                # action="callback", callback=lambda a,b,c,d: self.cmds.append("kernel_malloc_ranges"))

        # Java
        parser.add_option("-j", "--java-loaded-classes", help="enumerate Java LOADED CLASSES",
                action="callback", callback=lambda a,b,c,d: self.cmds.append("java_loaded_classes"))
        parser.add_option("--java-instances", help="enumerate Java OBJECT INSTANCES",
                action="callback", callback=lambda a,b,c,d: self.cmds.append("java_instances"))

        # ObjC
        parser.add_option("-o", "--objc-classes", help="enumerate ObjC CLASSES",
                action="callback", callback=lambda a,b,c,d: self.cmds.append("objc_classes"))
        parser.add_option("--objc-instances", help="enumerate ObjC INSTANCES",
                action="callback", callback=lambda a,b,c,d: self.cmds.append("objc_instances"))
        parser.add_option("--objc-protocols", help="enumerate ObjC PROTOCOLS",
                action="callback", callback=lambda a,b,c,d: self.cmds.append("objc_protocols"))

        # Options
        parser.add_option("--wait-init", help="wait until the module is initialized", action="store_true", default=False)

    def _needs_target(self):
        return True

    def _initialize(self, parser, options, args):
        self._options = options

    def _start(self):
        script = script_deploy(self._session)
        for cmd in self.cmds:
            fn = getattr(script.exports, cmd)
            print(fn())


def main():
    enumer = EnumerApplication()
    enumer.run()

if __name__ == "__main__":
    main()
