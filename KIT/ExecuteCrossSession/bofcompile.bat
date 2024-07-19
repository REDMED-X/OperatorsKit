@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc executecrosssession.c
move /y executecrosssession.obj executecrosssession.o

