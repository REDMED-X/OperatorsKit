@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc findhandle.c
move /y findhandle.obj findhandle.o
dumpbin /disasm findhandle.o > findhandle.disasm

