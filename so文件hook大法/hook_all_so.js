// hook_all_so.js - 用于hook所有加载的SO文件及其导出函数
setTimeout(function() {
    console.log("[+] 开始hook所有SO文件及其导出函数");
    
    // 存储已处理过的模块，避免重复处理
    var processedModules = {};
    
    // 处理单个模块的函数
    function processModule(module) {
        if (processedModules[module.name]) {
            return;
        }
        
        processedModules[module.name] = true;
        console.log("[+] 处理模块: " + module.name + " 基地址: " + module.base);
        
        // 获取并处理所有导出函数
        var exports = module.enumerateExports();
        console.log("[+] " + module.name + " 共有 " + exports.length + " 个导出函数");
        
        exports.forEach(function(exp) {
            if (exp.type == 'function') {
                console.log("[+] 函数名: " + exp.name + " 地址: " + exp.address);
                
                try {
                    // 对每个函数进行hook
                    Interceptor.attach(exp.address, {
                        onEnter: function(args) {
                            console.log("[CALL] " + module.name + "!" + exp.name);
                            
                            // 保存函数信息用于onLeave
                            this.moduleName = module.name;
                            this.funcName = exp.name;
                            
                            // 打印前4个参数（如果需要更多参数可以增加）
                            console.log("参数1: " + args[0]);
                            console.log("参数2: " + args[1]);
                            console.log("参数3: " + args[2]);
                            console.log("参数4: " + args[3]);
                            
                            // 如果需要，可以打印调用栈
                            console.log("调用栈:\n" + 
                                Thread.backtrace(this.context, Backtracer.ACCURATE)
                                .map(DebugSymbol.fromAddress).join("\n"));
                        },
                        onLeave: function(retval) {
                            console.log("[RETURN] " + this.moduleName + "!" + this.funcName + " => " + retval);
                            return retval;
                        }
                    });
                } catch(e) {
                    console.log("[!] Hook函数 " + exp.name + " 失败: " + e.message);
                }
            }
        });
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
    
    console.log("[+] 所有SO文件hook完成");
}, 0);

// 如果只想hook特定的SO文件，可以使用以下代码替换上面的代码
/*
setTimeout(function() {
    var targetModule = "libtarget.so"; // 替换为目标SO文件名
    var module = Process.findModuleByName(targetModule);
    
    if (module) {
        console.log("[+] 找到目标模块: " + module.name + " 基地址: " + module.base);
        
        // 获取并处理所有导出函数
        var exports = module.enumerateExports();
        console.log("[+] " + module.name + " 共有 " + exports.length + " 个导出函数");
        
        exports.forEach(function(exp) {
            if (exp.type == 'function') {
                console.log("[+] 函数名: " + exp.name + " 地址: " + exp.address);
                
                try {
                    // 对每个函数进行hook
                    Interceptor.attach(exp.address, {
                        onEnter: function(args) {
                            console.log("[CALL] " + module.name + "!" + exp.name);
                            
                            // 保存函数信息用于onLeave
                            this.funcName = exp.name;
                            
                            // 打印前4个参数
                            console.log("参数1: " + args[0]);
                            console.log("参数2: " + args[1]);
                            console.log("参数3: " + args[2]);
                            console.log("参数4: " + args[3]);
                        },
                        onLeave: function(retval) {
                            console.log("[RETURN] " + this.funcName + " => " + retval);
                            return retval;
                        }
                    });
                } catch(e) {
                    console.log("[!] Hook函数 " + exp.name + " 失败: " + e.message);
                }
            }
        });
    } else {
        console.log("[!] 未找到目标模块: " + targetModule);
    }
}, 0);
*/ 