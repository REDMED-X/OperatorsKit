@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc dllenvhijacking.c
move /y dllenvhijacking.obj dllenvhijacking.o
dumpbin /disasm dllenvhijacking.o > dllenvhijacking.disasm

