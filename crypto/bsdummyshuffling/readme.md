该程序基于 Alex Biryukov 和 Aleksei Udovenko 的初始工作。
https://github.com/cryptolu/whitebox

minimal.pl 是 GENERATE 的直接调用程序，会调用 minimal.py
minimal.py 是生成程序

whitebox 文件夹下的内容生成程序所依赖的实现
    ciphers是SM4的比特实现
    templates是生成的白盒加密程序的模板
    masking.py记录掩码结构与重载运算实现(实现了ISW和BU两种掩码)
    orderer.py按顺序排列电路计算
    prng.py实现伪随机数
    serialize.py实现序列化
    whibox.py是生成并输出白盒程序的主要实现
    tree记录了node和op等基本结构
        node 是AST节点基类，用于构建可递归求值的表达式树
        bitnode 是一个基于位运算的节点类，继承自 Node，主要用于构建逻辑表达式树
        op 实现逻辑操作（AND/OR/XOR/NOT），支持链式调用
        optbitnode 继承自 BitNode，在保留基础功能的同时，简化运算提升执行效率
