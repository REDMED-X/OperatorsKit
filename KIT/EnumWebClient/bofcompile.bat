@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc enumwebclient.c
move /y enumwebclient.obj enumwebclient.o


