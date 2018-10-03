rpc.exports = {
    // Native
    modules: function() {
        return Process.enumerateModulesSync();
    },

    moduleImports: function(module) {
        return Module.enumerateImportsSync(module);
    },

    moduleExports: function(module) {
        return Module.enumerateExportsSync(module);
    },

    moduleSymbols: function(module) {
        return Module.enumerateSymbolsSync(module);
    },

/*
    ranges: function() {
        return Process.enumerateThreadsSync();
    },

    mallocRanges: function() {
        return Process.enumerateThreadsSync();
    },
*/
    threads: function() {
        return Process.enumerateThreadsSync();
    },

    // Kernel
    kernelModules: function() {
        return Kernel.enumerateModulesSync();
    },

/*
    kernelRanges: function() {
        return Kernel.enumerateThreadsSync();
    },

    kernelMallocRanges: function() {
        return Kernel.enumerateThreadsSync();
    },
*/

    // Java
    javaLoadedClasses: function(filter) {
        Java.perform(function() {
            return Java.enumerateLoadedClassesSync()
        })
    },

    javaClassLoaders: function(filter) {
        Java.perform(function() {
            return Java.enumerateClassLoadersSync()
        })
    },

    javaInstances: function(className) {
        Java.perform(function() {
            return Java.chooseSync(className);
        });
    },

    // ObjC
    objcClasses: function() {
        return ObjC.classes;
    },

    objcInstances: function(module) {
        return ObjC.choose(module);
    },

    objcProtocols: function(module) {
        return ObjC.protocols;
    }
}
