@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc enumdrives.c
move /y enumdrives.obj enumdrives.o

