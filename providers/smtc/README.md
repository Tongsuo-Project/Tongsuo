# Build SMTC

build SMTC with atf_slibce and atf_sdf as follows:

```
./config no-shared no-module enable-ntls enable-smtc enable-smtc-debug enable-ssl-trace enable-trace --debug --prefix=/path/to/tongsuo --libdir=/path/to/tongsuo/lib/ --api=1.1.1 --with-rand-seed=rtcode,rtmem,rtsock -DTONGSUO_RAND_GM_SRNG --strict-warnings enable-atf_slibce --with-atf_slibce-lib=../libatf_slibce.a --smtc-pubkey=/tmp/smtcpub.key enable-sdf-lib --with-sdf-lib=/atf-libs-static/libatf_sdf.a --with-sdf-include=/atf-includes/atf-sdf

make -j

make install
```

# Install SMTC

```
tongsuo mod -install -module /bin/tongsuo -sigfile signature.bin
```

# SMTC Self Test

```
tongsuo mod -test
```
