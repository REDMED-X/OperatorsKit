@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc enumshares.c
move /y enumshares.obj enumshares.o


