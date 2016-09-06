# readex
It's a simple dex file format parser. 

```
> make test
 
=== readex 0.01 ===

Dex Header:
 Magic: 64 65 78 0a 30 33 35 00    (dex\n035\0)
 Checksum:                       14305E04
 Signature:                      E5193F8E1A663EFAC1EA72D63F122A00B69FA1D5
 File Size:                      2E0(736) bytes
 Header Size:                    70(112) bytes
 Endian Tag:                     little endian(12345678)
 LinkSize:                       0(0)
 Link Offset:                    0(0)
 Map Offset:                     240(576)
 String ID Size:                 E(14)
 String ID Offset:               70(112)
 Type ID Size:                   7(7)
 Type ID Offset:                 A8(168)
 Method Proto Size:              3(3)
 Method Proto Offset:            C4(196)
 Field ID Size:                  1(1)
 Field ID Offset:                E8(232)
 Method ID Size:                 4(4)
 Method ID Offset:               F0(240)
 Class Define Size:              1(1)
 Class Define Offset:            110(272)
 Data Size:                      1B0(432)
 Data Offset:                    130(304)
...
...
...
Class 0:
 name: Hello
 flag: public 
 super: java.lang.Object
 source: Hello.java
 class data: 
  Direct Method:
    public constructor void <init>()
    public static void main(java.lang.String[])
```
