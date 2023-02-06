@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc loadlib.c
move /y loadlib.obj loadlib.o
dumpbin /disasm loadlib.o > loadlib.disasm

