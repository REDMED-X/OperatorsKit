@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc findsysmon.c
move /y findsysmon.obj findsysmon.o

