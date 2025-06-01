// hook_specific_so.js - 针对特定SO文件和特定函数的hook脚本
Java.perform(function() {
    console.log("[+] 开始hook特定SO文件的特定函数");
    
    // 配置区域 - 根据实际需求修改
    var targetSoName = "libtarget.so";  // 目标SO文件名，需要修改为实际目标
    var targetFunctions = [
        // 导出函数名列表
        "Java_com_example_app_NativeLib_encrypt",
        "Java_com_example_app_NativeLib_decrypt",
        "sign",
        "verify"
    ];
    
    var targetOffsets = [
        // 函数偏移地址列表 (相对于SO基址)
        0x1000,  // 示例偏移，需要修改为实际偏移
        0x2000   // 示例偏移，需要修改为实际偏移
    ];
    
    // 查找目标SO文件
    var targetModule = null;
    Process.enumerateModules().forEach(function(module) {
        if (module.name === targetSoName) {
            targetModule = module;
            console.log("[+] 找到目标模块: " + module.name);
            console.log("    基地址: " + module.base);
            console.log("    大小: " + module.size);
            console.log("    文件路径: " + module.path);
            return;
        }
    });
    
    if (!targetModule) {
        console.log("[!] 未找到目标模块: " + targetSoName);
        
        // 监听模块加载事件，等待目标模块加载
        Process.addModuleLoadCallback(function(module) {
            if (module.name === targetSoName) {
                console.log("[+] 目标模块已加载: " + module.name);
                targetModule = module;
                hookTargetModule(module);
            }
        });
        return;
    }
    
    hookTargetModule(targetModule);
    
    function hookTargetModule(module) {
        // 1. Hook指定的导出函数
        console.log("[+] 开始hook指定的导出函数...");
        var exports = module.enumerateExports();
        
        exports.forEach(function(exp) {
            if (exp.type === 'function') {
                // 检查是否是目标函数
                if (targetFunctions.indexOf(exp.name) !== -1 || 
                    targetFunctions.some(function(pattern) {
                        return exp.name.indexOf(pattern) !== -1;
                    })) {
                    console.log("[+] 找到目标导出函数: " + exp.name + " 地址: " + exp.address);
                    
                    try {
                        Interceptor.attach(exp.address, {
                            onEnter: function(args) {
                                console.log("[CALL] " + module.name + "!" + exp.name);
                                this.funcName = exp.name;
                                
                                // 保存参数用于分析
                                this.args = [];
                                for (var i = 0; i < 8; i++) {
                                    this.args.push(args[i]);
                                }
                                
                                // 打印调用栈
                                console.log("调用栈:\n" + 
                                    Thread.backtrace(this.context, Backtracer.ACCURATE)
                                    .map(DebugSymbol.fromAddress).join("\n"));
                                
                                // 尝试打印参数内容
                                for (var i = 0; i < 8; i++) {
                                    try {
                                        // 尝试作为字符串读取
                                        var str = Memory.readUtf8String(args[i]);
                                        if (str && str.length > 0 && str.length < 1000) {
                                            console.log("参数" + i + " (字符串): " + str);
                                        } else {
                                            // 尝试作为字节数组读取
                                            try {
                                                // 假设第二个参数可能是长度
                                                if (i === 0 && args[1] && args[1].toInt32) {
                                                    var len = parseInt(args[1].toInt32());
                                                    if (len > 0 && len < 1000) {
                                                        var bytes = Memory.readByteArray(args[i], len);
                                                        console.log("参数" + i + " (字节数组): " + bytesToHex(bytes));
                                                    }
                                                }
                                            } catch (e) {}
                                        }
                                    } catch (e) {}
                                    
                                    // 打印参数值
                                    console.log("参数" + i + " (值): " + args[i]);
                                }
                            },
                            onLeave: function(retval) {
                                console.log("[RETURN] " + this.funcName + " => " + retval);
                                
                                // 尝试打印返回值内容
                                try {
                                    var retStr = Memory.readUtf8String(retval);
                                    if (retStr && retStr.length > 0 && retStr.length < 1000) {
                                        console.log("返回字符串: " + retStr);
                                    }
                                } catch (e) {}
                                
                                return retval;
                            }
                        });
                        console.log("[+] 成功hook函数: " + exp.name);
                    } catch(e) {
                        console.log("[!] Hook函数 " + exp.name + " 失败: " + e.message);
                    }
                }
            }
        });
        
        // 2. Hook指定的偏移地址
        console.log("[+] 开始hook指定的偏移地址...");
        targetOffsets.forEach(function(offset) {
            var targetAddr = module.base.add(offset);
            console.log("[+] 尝试hook地址: " + targetAddr + " (偏移: 0x" + offset.toString(16) + ")");
            
            try {
                Interceptor.attach(targetAddr, {
                    onEnter: function(args) {
                        console.log("[CALL] " + module.name + "!函数@0x" + offset.toString(16));
                        
                        // 保存参数用于分析
                        this.args = [];
                        for (var i = 0; i < 8; i++) {
                            this.args.push(args[i]);
                        }
                        
                        // 打印调用栈
                        console.log("调用栈:\n" + 
                            Thread.backtrace(this.context, Backtracer.ACCURATE)
                            .map(DebugSymbol.fromAddress).join("\n"));
                        
                        // 打印参数
                        for (var i = 0; i < 8; i++) {
                            console.log("参数" + i + ": " + args[i]);
                        }
                    },
                    onLeave: function(retval) {
                        console.log("[RETURN] " + module.name + "!函数@0x" + offset.toString(16) + " => " + retval);
                        return retval;
                    }
                });
                console.log("[+] 成功hook地址: " + targetAddr);
            } catch(e) {
                console.log("[!] Hook地址 " + targetAddr + " 失败: " + e.message);
            }
        });
        
        // 3. 搜索特定内存模式并hook
        console.log("[+] 开始搜索特定内存模式...");
        
        // 示例：搜索ARM指令 "MOVS R0, #1; BX LR" (0x01200020)
        var pattern = "01 20 00 20";  // 需要修改为实际需要搜索的模式
        
        Memory.scan(module.base, module.size, pattern, {
            onMatch: function(address, size) {
                console.log("[+] 找到匹配的内存模式: " + address);
                
                try {
                    Interceptor.attach(address, {
                        onEnter: function(args) {
                            console.log("[CALL] " + module.name + "!模式匹配函数@" + address);
                            
                            // 打印调用栈
                            console.log("调用栈:\n" + 
                                Thread.backtrace(this.context, Backtracer.ACCURATE)
                                .map(DebugSymbol.fromAddress).join("\n"));
                        },
                        onLeave: function(retval) {
                            console.log("[RETURN] " + module.name + "!模式匹配函数@" + address + " => " + retval);
                            return retval;
                        }
                    });
                    console.log("[+] 成功hook匹配地址: " + address);
                } catch(e) {
                    console.log("[!] Hook匹配地址 " + address + " 失败: " + e.message);
                }
            },
            onComplete: function() {
                console.log("[+] 内存模式搜索完成");
            }
        });
        
        // 4. 监听JNI函数注册
        console.log("[+] 开始监听JNI函数注册...");
        
        var RegisterNatives = Module.findExportByName("libart.so", "_ZN3art3JNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi");
        if (RegisterNatives) {
            console.log("[+] 找到RegisterNatives函数: " + RegisterNatives);
            
            Interceptor.attach(RegisterNatives, {
                onEnter: function(args) {
                    var env = args[0];
                    var clazz = args[1];
                    var methods = args[2];
                    var size = args[3].toInt32();
                    
                    // 获取类名
                    var className = Java.vm.tryGetEnv().getClassName(clazz);
                    console.log("[RegisterNatives] 类: " + className + ", 方法数: " + size);
                    
                    // 遍历注册的方法
                    for (var i = 0; i < size; i++) {
                        var methodsPtr = methods.add(i * Process.pointerSize * 3);
                        var name = Memory.readCString(Memory.readPointer(methodsPtr));
                        var signature = Memory.readCString(Memory.readPointer(methodsPtr.add(Process.pointerSize)));
                        var fnPtr = Memory.readPointer(methodsPtr.add(Process.pointerSize * 2));
                        
                        console.log("[RegisterNatives] 方法: " + name + ", 签名: " + signature + ", 函数地址: " + fnPtr);
                        
                        // 如果方法属于目标SO文件，则hook它
                        if (fnPtr >= module.base && fnPtr < module.base.add(module.size)) {
                            console.log("[+] 找到目标SO中的JNI方法: " + name);
                            
                            try {
                                Interceptor.attach(fnPtr, {
                                    onEnter: function(args) {
                                        console.log("[CALL JNI] " + name);
                                        this.methodName = name;
                                        
                                        // JNI环境和jobject是前两个参数
                                        console.log("JNIEnv: " + args[0]);
                                        console.log("jobject/jclass: " + args[1]);
                                        
                                        // 打印其他参数
                                        for (var i = 2; i < 8; i++) {
                                            console.log("参数" + (i-2) + ": " + args[i]);
                                        }
                                    },
                                    onLeave: function(retval) {
                                        console.log("[RETURN JNI] " + this.methodName + " => " + retval);
                                        return retval;
                                    }
                                });
                                console.log("[+] 成功hook JNI方法: " + name);
                            } catch(e) {
                                console.log("[!] Hook JNI方法 " + name + " 失败: " + e.message);
                            }
                        }
                    }
                }
            });
        }
    }
    
    // 辅助函数：将字节数组转换为十六进制字符串
    function bytesToHex(data) {
        var result = "";
        for (var i = 0; i < data.length; i++) {
            result += ('0' + data[i].toString(16)).slice(-2);
        }
        return result;
    }
    
    console.log("[+] hook脚本设置完成");
}); 