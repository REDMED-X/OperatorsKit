@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc enumrwx.c
move /y enumrwx.obj enumrwx.o