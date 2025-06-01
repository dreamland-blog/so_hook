// hook_and_modify_so.js - 用于动态修改SO函数行为的脚本
Java.perform(function() {
    console.log("[+] 开始hook并修改SO函数行为");
    
    // 配置区域 - 根据实际需求修改
    var targetSoName = "libtarget.so";  // 目标SO文件名，需要修改为实际目标
    
    // 查找目标SO文件
    var targetModule = Process.findModuleByName(targetSoName);
    if (!targetModule) {
        console.log("[!] 未找到目标模块: " + targetSoName);
        
        // 监听模块加载事件，等待目标模块加载
        Process.addModuleLoadCallback(function(module) {
            if (module.name === targetSoName) {
                console.log("[+] 目标模块已加载: " + module.name);
                targetModule = module;
                hookAndModify(module);
            }
        });
        return;
    }
    
    hookAndModify(targetModule);
    
    function hookAndModify(module) {
        console.log("[+] 开始修改SO函数行为: " + module.name);
        
        // 示例1: 替换加密函数，使其返回明文（不加密）
        var encryptFunc = Module.findExportByName(module.name, "encrypt");
        if (encryptFunc) {
            console.log("[+] 找到加密函数: " + encryptFunc);
            
            Interceptor.attach(encryptFunc, {
                onEnter: function(args) {
                    console.log("[CALL] encrypt");
                    
                    // 保存参数信息
                    this.inputBuf = args[0];
                    this.inputLen = args[1].toInt32();
                    this.outputBuf = args[2];
                    
                    // 打印原始输入数据
                    if (this.inputLen > 0 && this.inputLen < 1000) {
                        var inputData = Memory.readByteArray(this.inputBuf, this.inputLen);
                        console.log("原始输入数据: " + bytesToHex(inputData));
                        
                        try {
                            var inputStr = Memory.readUtf8String(this.inputBuf, this.inputLen);
                            console.log("输入字符串: " + inputStr);
                        } catch (e) {}
                    }
                },
                onLeave: function(retval) {
                    console.log("[RETURN] encrypt => " + retval);
                    
                    // 修改行为: 直接将输入数据复制到输出缓冲区（跳过加密）
                    if (this.inputBuf && this.outputBuf && this.inputLen > 0) {
                        Memory.copy(this.outputBuf, this.inputBuf, this.inputLen);
                        console.log("[MODIFY] 已跳过加密，直接复制原始数据");
                    }
                    
                    // 如果函数返回值是输出长度，确保返回正确的长度
                    if (retval.toInt32() !== this.inputLen) {
                        console.log("[MODIFY] 修改返回值为: " + this.inputLen);
                        retval.replace(this.inputLen);
                    }
                    
                    return retval;
                }
            });
        }
        
        // 示例2: 修改签名验证函数，使其始终返回成功
        var verifyFunc = Module.findExportByName(module.name, "verify");
        if (verifyFunc) {
            console.log("[+] 找到验证函数: " + verifyFunc);
            
            Interceptor.attach(verifyFunc, {
                onEnter: function(args) {
                    console.log("[CALL] verify");
                    
                    // 打印参数信息
                    for (var i = 0; i < 4; i++) {
                        console.log("参数" + i + ": " + args[i]);
                    }
                },
                onLeave: function(retval) {
                    console.log("[RETURN] verify 原始返回值: " + retval);
                    
                    // 修改行为: 始终返回成功 (1)
                    console.log("[MODIFY] 修改返回值为: 1 (成功)");
                    retval.replace(1);
                    
                    return retval;
                }
            });
        }
        
        // 示例3: 修改内存中的指令（例如，将条件跳转改为无条件跳转）
        // 注意: 这需要精确知道目标指令的地址和架构
        var patchAddr = module.base.add(0x1234);  // 示例地址，需要修改为实际地址
        console.log("[+] 尝试修改指令地址: " + patchAddr);
        
        // 确保内存可写
        Memory.protect(patchAddr, 4, 'rwx');
        
        // 示例: ARM架构下修改条件分支指令
        // 将条件分支 (BNE - Branch if Not Equal) 改为无条件分支 (B - Branch Always)
        try {
            // 读取原始指令
            var originalBytes = Memory.readByteArray(patchAddr, 4);
            console.log("[PATCH] 原始指令: " + bytesToHex(originalBytes));
            
            // 修改指令 (示例: 将条件跳转改为无条件跳转)
            // 对于ARM指令，通常只需要修改条件码部分
            // 这里是一个示例，实际修改需要根据具体的指令编码
            var patchedBytes = new Uint8Array([0xEA, 0x00, 0x00, 0x00]);  // 示例无条件跳转指令
            Memory.writeByteArray(patchAddr, patchedBytes);
            
            console.log("[PATCH] 已修改指令: " + bytesToHex(Memory.readByteArray(patchAddr, 4)));
        } catch (e) {
            console.log("[!] 修改指令失败: " + e.message);
        }
        
        // 示例4: 替换整个函数实现
        var targetFunc = Module.findExportByName(module.name, "target_function");
        if (targetFunc) {
            console.log("[+] 找到目标函数: " + targetFunc);
            
            // 创建一个新的NativeCallback作为替代函数
            var replacementFunc = new NativeCallback(function(arg1, arg2) {
                console.log("[REPLACE] 已替换target_function的实现");
                console.log("参数1: " + arg1);
                console.log("参数2: " + arg2);
                
                // 自定义实现逻辑
                return 1;  // 返回成功
            }, 'int', ['pointer', 'int']);
            
            // 替换原函数
            Interceptor.replace(targetFunc, replacementFunc);
            console.log("[+] 已完全替换函数实现");
        }
        
        // 示例5: Hook JNI函数并修改Java对象
        var jniFunc = Module.findExportByName(module.name, "Java_com_example_app_NativeLib_processData");
        if (jniFunc) {
            console.log("[+] 找到JNI函数: " + jniFunc);
            
            Interceptor.attach(jniFunc, {
                onEnter: function(args) {
                    console.log("[CALL] JNI processData");
                    
                    // 保存JNI环境和Java对象
                    this.env = args[0];
                    this.javaObj = args[1];
                    
                    // 如果有字符串参数，可以读取并修改
                    if (args[2] != 0) {
                        var jstring = args[2];
                        
                        // 获取Java字符串的内容
                        var getStringUTFChars = new NativeFunction(
                            Memory.readPointer(Memory.readPointer(this.env).add(Process.pointerSize * 0x15)),
                            'pointer', ['pointer', 'pointer', 'pointer']
                        );
                        
                        var str = getStringUTFChars(this.env, jstring, ptr(0));
                        var inputStr = Memory.readUtf8String(str);
                        console.log("输入Java字符串: " + inputStr);
                        
                        // 可以在这里修改Java字符串的处理逻辑
                        this.originalInput = inputStr;
                    }
                },
                onLeave: function(retval) {
                    console.log("[RETURN] JNI processData => " + retval);
                    
                    // 如果返回值是jstring，可以替换为自定义字符串
                    if (retval != 0) {
                        // 创建新的Java字符串
                        var newString = "已被修改的返回值 - 原始输入: " + this.originalInput;
                        
                        var newStringClass = Java.use("java.lang.String");
                        var newJavaString = newStringClass.$new(newString);
                        
                        // 替换返回值
                        retval.replace(ptr(newJavaString));
                        console.log("[MODIFY] 已替换返回的Java字符串");
                    }
                    
                    return retval;
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
    
    console.log("[+] hook和修改脚本设置完成");
}); 