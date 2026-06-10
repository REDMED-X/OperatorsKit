@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc authenticatehttp.c
move /y authenticatehttp.obj authenticatehttp.o

