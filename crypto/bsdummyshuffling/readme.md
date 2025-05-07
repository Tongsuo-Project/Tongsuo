该程序基于 Alex Biryukov 和 Aleksei Udovenko 的初始工作。
https://github.com/cryptolu/whitebox

minimal.pl 是 GENERATE 的直接调用程序，会调用 minimal.py
minimal.py 是生成程序
whitebox 文件夹下的内容生成程序所依赖的实现

其中ciphers是SM4的比特实现
templates是生成的白盒加密程序的模板
tree记录了node和op等基本结构
masking.py记录掩码结构与重载运算实现(实现了ISW和BU两种掩码)
orderer.py按顺序排列电路计算
prng.py实现伪随机数
serialize.py实现序列化
utils.py实现bin和str的互相转化
whibox.py是生成并输出白盒程序的主要实现
