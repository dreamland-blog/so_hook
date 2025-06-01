hook_all_so.js - 基础版本，用于hook所有加载的SO文件及其导出函数
hook_all_so_advanced.js - 高级版本，不仅hook导出函数，还能hook内部函数和符号
hook_specific_so.js - 针对特定SO文件和特定函数的hook脚本，包含更多详细分析功能
hook_and_modify_so.js - 用于动态修改SO函数行为的脚本，可以替换函数实现、修改返回值等
使用这些脚本时，需要根据实际目标应用进行适当修改：
修改目标SO文件名
调整需要hook的函数名或地址偏移
根据实际需求修改hook行为
