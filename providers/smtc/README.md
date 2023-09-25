# 构建SMTC

```
./config  enable-smtc enable-ntls no-shared enable-ssl-trace --prefix=/opt/tongsuo -Wl,-rpath,/opt/tongsuo/lib64

make

make install
```

# 配置SMTC

```
/opt/tongsuo/bin/tongsuo mod -module /opt/tongsuo/bin/tongsuo -provider_name smtc -section_name smtc_sect -show_selftest -out /opt/tongsuo/ssl/smtcmodule.cnf

# 修改/opt/tongsuo/ssl/openssl.cnf，包含smtcmodule.cnf，设置smtc section
sed -i -e 's|^# .include smtcmodule.cnf|.include /opt/tongsuo/ssl/smtcmodule.cnf|;s/^# smtc = smtc_sect/smtc = smtc_sect/' /opt/tongsuo/ssl/openssl.cnf

```

# SMTC自测试

```
/opt/tongsuo/bin/tongsuo mod -test
```
