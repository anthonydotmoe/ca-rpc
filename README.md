# ca-rpc

Perfrom a certificate request to a Windows Certification Authority using
DCE/RPC with Kerberos authentication.

# Building

The [`dcerpc`](https://github.com/dcerpc/dcerpc) library is required for
building this program. You need to build it with the `--enable-gss_negotiate`
flag. I also needed to use `libtoolize` and `autoreconf` to get it to build at
all:

```
cd dcerpc
libtoolize
autoreconf -fi
./configure --enable-gss_negotiate
make
sudo make install
```

Then you can build the actual program:

```
mkdir build
cd build
cmake ..
make
```

## Notes

IDL files required for compilation:

* [MS-ICPR]\: Provides ICertPassage definition
    * [MS-DTYP]\: Provides Windows Data Types
