@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc enumfiles.c
move /y enumfiles.obj enumfiles.o

