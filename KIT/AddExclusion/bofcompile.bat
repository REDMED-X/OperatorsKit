@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc addexclusion.c
move /y addexclusion.obj addexclusion.o

