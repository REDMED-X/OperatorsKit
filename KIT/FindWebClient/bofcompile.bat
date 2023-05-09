@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc findwebclient.c
move /y findwebclient.obj findwebclient.o


