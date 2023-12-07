@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc delexclusion.c
move /y delexclusion.obj delexclusion.o

