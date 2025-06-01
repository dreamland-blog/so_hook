// hook_all_so_advanced.js - 高级版本：hook所有SO文件的导出函数、内部函数和符号
Java.perform(function() {
    console.log("[+] 开始高级hook所有SO文件");
    
    // 存储已处理过的模块，避免重复处理
    var processedModules = {};
    
    // 处理单个模块的函数
    function processModule(module) {
        if (processedModules[module.name]) {
            return;
        }
        
        processedModules[module.name] = true;
        console.log("[+] 处理模块: " + module.name);
        console.log("    基地址: " + module.base);
        console.log("    大小: " + module.size);
        console.log("    文件路径: " + module.path);
        
        // 1. 处理导出函数
        console.log("[+] 开始处理导出函数...");
        var exports = module.enumerateExports();
        console.log("    共有 " + exports.length + " 个导出函数");
        
        exports.forEach(function(exp) {
            if (exp.type == 'function') {
                console.log("    [EXPORT] 函数名: " + exp.name + " 地址: " + exp.address);
                
                try {
                    Interceptor.attach(exp.address, {
                        onEnter: function(args) {
                            console.log("[CALL] " + module.name + "!" + exp.name);
                            this.moduleName = module.name;
                            this.funcName = exp.name;
                            
                            // 保存参数用于分析
                            this.args = [];
                            for (var i = 0; i < 8; i++) { // 保存前8个参数
                                this.args.push(args[i]);
                            }
                            
                            // 打印调用栈
                            console.log("调用栈:\n" + 
                                Thread.backtrace(this.context, Backtracer.ACCURATE)
                                .map(DebugSymbol.fromAddress).join("\n"));
                        },
                        onLeave: function(retval) {
                            console.log("[RETURN] " + this.moduleName + "!" + this.funcName + " => " + retval);
                            
                            // 尝试打印参数和返回值的内容（如果是指针）
                            try {
                                // 检查返回值是否是字符串指针
                                var retStr = Memory.readUtf8String(retval);
                                if (retStr && retStr.length > 0 && retStr.length < 1000) {
                                    console.log("返回字符串: " + retStr);
                                }
                                
                                // 检查参数是否是字符串指针
                                for (var i = 0; i < this.args.length; i++) {
                                    try {
                                        var argStr = Memory.readUtf8String(this.args[i]);
                                        if (argStr && argStr.length > 0 && argStr.length < 1000) {
                                            console.log("参数" + i + "字符串: " + argStr);
                                        }
                                    } catch (e) {}
                                }
                            } catch (e) {}
                            
                            return retval;
                        }
                    });
                } catch(e) {
                    console.log("    [!] Hook函数 " + exp.name + " 失败: " + e.message);
                }
            }
        });
        
        // 2. 处理导入函数
        console.log("[+] 开始处理导入函数...");
        var imports = module.enumerateImports();
        console.log("    共有 " + imports.length + " 个导入函数");
        
        imports.forEach(function(imp) {
            console.log("    [IMPORT] 函数名: " + imp.name + " 模块: " + imp.module + " 地址: " + imp.address);
            
            // 可以选择性地hook导入函数
            // 这里不进行hook，因为导入函数通常在其所属模块中已经被hook
        });
        
        // 3. 处理符号
        console.log("[+] 开始处理符号...");
        var symbols = module.enumerateSymbols();
        console.log("    共有 " + symbols.length + " 个符号");
        
        symbols.forEach(function(sym) {
            if (sym.type == 'function') {
                console.log("    [SYMBOL] 函数名: " + sym.name + " 地址: " + sym.address);
                
                // 可以选择性地hook特定的内部函数
                // 例如，只hook名称包含特定关键字的函数
                var keywords = ["encrypt", "decrypt", "sign", "verify", "hash", "md5", "sha", "aes", "des", "rsa"];
                var shouldHook = keywords.some(function(keyword) {
                    return sym.name.toLowerCase().indexOf(keyword) !== -1;
                });
                
                if (shouldHook) {
                    try {
                        Interceptor.attach(sym.address, {
                            onEnter: function(args) {
                                console.log("[CALL] " + module.name + "!" + sym.name + " (内部函数)");
                                this.moduleName = module.name;
                                this.funcName = sym.name;
                                
                                // 保存参数用于分析
                                this.args = [];
                                for (var i = 0; i < 8; i++) {
                                    this.args.push(args[i]);
                                }
                            },
                            onLeave: function(retval) {
                                console.log("[RETURN] " + this.moduleName + "!" + this.funcName + " => " + retval);
                                return retval;
                            }
                        });
                        console.log("    [+] 成功hook内部函数: " + sym.name);
                    } catch(e) {
                        console.log("    [!] Hook内部函数 " + sym.name + " 失败: " + e.message);
                    }
                }
            }
        });
        
        // 4. 处理特定内存区域的函数
        console.log("[+] 开始扫描可能的函数...");
        
        // 这部分需要根据目标应用进行定制
        // 以下是一个示例，扫描特定的内存区域并尝试hook可能的函数
        /*
        var targetAddr = module.base.add(0x1000); // 示例地址，需要根据实际情况调整
        try {
            Interceptor.attach(targetAddr, {
                onEnter: function(args) {
                    console.log("[CALL] " + module.name + "!未知函数@" + targetAddr);
                    console.log("调用栈:\n" + 
                        Thread.backtrace(this.context, Backtracer.ACCURATE)
                        .map(DebugSymbol.fromAddress).join("\n"));
                },
                onLeave: function(retval) {
                    console.log("[RETURN] " + module.name + "!未知函数@" + targetAddr + " => " + retval);
                    return retval;
                }
            });
        } catch(e) {
            console.log("    [!] Hook地址 " + targetAddr + " 失败: " + e.message);
        }
        */
    }
    
    // 处理当前已加载的所有模块
    Process.enumerateModules().forEach(function(module) {
        // 只处理.so文件
        if (module.name.endsWith(".so")) {
            processModule(module);
        }
    });
    
    // 监听新模块加载事件
    Process.addModuleLoadCallback(function(module) {
        // 只处理.so文件
        if (module.name.endsWith(".so")) {
            console.log("[+] 新模块加载: " + module.name);
            processModule(module);
        }
    });
    
    // 5. 监控内存分配
    console.log("[+] 开始监控内存分配...");
    MemoryAccessMonitor.enable({
        onAccess: function(details) {
            console.log("[MEMORY] 访问: " + details.operation + " 地址: " + details.from + " -> " + details.address);
        }
    });
    
    console.log("[+] 所有SO文件hook完成");
});

// 辅助函数：将字节数组转换为十六进制字符串
function bytesToHex(data) {
    var result = "";
    for (var i = 0; i < data.length; i++) {
        result += ('0' + data[i].toString(16)).slice(-2);
    }
    return result;
}

// 辅助函数：打印十六进制转储
function hexdump(data) {
    return hexdump(data, {
        offset: 0,
        length: data.length,
        header: true,
        ansi: false
    });
} 