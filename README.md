## 一些 Android APK 脱壳的小 demo

仅仅是些小DEMO，不断更新……

1. mem_dumper 可脱 com.qihoo.util 下 3 文件版本的壳

> Configuration.smali

> QHDialog.smali

> StubApp92791245.smali (数字随机)


2. memcmp_hook 可脱 com.qihoo.util 下 2 文件版本的壳

> Configuration.smali

> StubApplication.smali

3. 3rd_party_hook 用于 hook 应用自带的 libs ，测试用的 libshanpao_jni.so ，hook 其 aes_encrypt_cbc() 函数