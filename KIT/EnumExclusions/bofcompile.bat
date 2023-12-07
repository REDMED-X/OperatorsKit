@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc enumexclusions.c
move /y enumexclusions.obj enumexclusions.o

