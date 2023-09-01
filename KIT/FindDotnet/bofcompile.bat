@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc finddotnet.c
move /y finddotnet.obj finddotnet.o
