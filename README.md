# AvoidRandomKill
对原项目的AES加密部分以及Shellcode加载器代码一些优化更改。

# AESloader
将原项目的输入C格式的shellcode成读取目录下读取shellcode.bin，并且每次运行AESloader会随机生成不同AES_KEY，AES_IV值。        
![image](https://github.com/user-attachments/assets/f386ce1e-c26c-4b78-bc88-f8b778373f9f)

# AvoidRandomKill
优化了原项目加载器中大多数的混乱逻辑分支，使其代码更加工整美观。并且使其能够再次免杀部分AV软件避免了导致落地查杀。

并且在此声明并未对加载器代码进行过多的更改，原项目（AvoidRandomKill）已经被大部分的AV软件查杀，在不对加载器代码进行一定的更改是无法保持加载器的免杀性质，该分支项目仅作为一个参考价值。

# 免杀性
火绒静态查杀
![image](https://github.com/user-attachments/assets/24408683-3cdb-4225-8dcc-036d322c180a)
火绒动态查杀
![image](https://github.com/user-attachments/assets/66d24d12-70e9-4047-8f2f-b41241bc0d13)

某数字（某数字沙箱云结果）（提交了两个样本）（1.通过ResourceHack添加可信资源避免被QVM查杀）（2.未添加任何可信资源直接编译）
![image](https://github.com/user-attachments/assets/f67ae167-9d2c-4325-b2f4-9471f1543f39)
![image](https://github.com/user-attachments/assets/4ad1b0f1-cc03-4866-84dc-dd1b505a1e35)

某数字沙箱云任务报告：
https://ata.360.net/report/589233153612800
https://ata.360.net/report/589233153612800

微步云沙箱：
![image](https://github.com/user-attachments/assets/f84e2ba7-d19e-4c50-870f-1cfa200d41b6)

https://s.threatbook.com/report/file/01e42d9bb64a49aa082fb4db70ed74ba1e9a26a904c071cb135d54ec1f0d7f3e

Windows Defender静态查杀
![image](https://github.com/user-attachments/assets/f1bf8cb2-8e7c-4e9a-831c-19423db9150b)
Windows Defender动态查杀
被查杀

# 结语
现有的反沙箱手段已然无法对抗日渐成熟的沙箱系统，这本身也是免杀技术与AV软件不断攻防对抗的成果，通过微步云沙箱结果也可以显然看出目前的反沙箱代码已经被市面上成熟的沙箱系统反制，为了与其对抗需要使用更加先进的反沙箱技术。
