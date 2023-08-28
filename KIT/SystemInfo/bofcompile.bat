@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc systeminfo.c
move /y systeminfo.obj systeminfo.o

