@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc enumwsc.c
move /y enumwsc.obj enumwsc.o


