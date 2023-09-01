@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc blindeventlog.c
move /y blindeventlog.obj blindeventlog.o

