@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc findrwx.c
move /y findrwx.obj findrwx.o