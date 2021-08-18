# PBKDF2.Key

#### 介绍
PBKDF2(Password-Based Key Derivation Function)是一个用来导出密钥的函数，常用于生成加密的密码。它的基本原理是通过一个伪随机函数（例如HMAC函数），把明文和一个盐值作为输入参数，然后重复进行运算，并最终产生密钥。如果重复的次数足够大，破解的成本就会变得很高。而盐值的添加也会增加“彩虹表”攻击的难度。

##### 一次在使用pyton需要中有看到 PBKDF2.Key 加密 后面尝试在net中查找半天没有找到，这次又在Gogi的开源项目中看到这个算法 ，于是打算按照GO语言重写一遍这个算法。