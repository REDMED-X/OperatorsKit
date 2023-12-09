@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc dllcomhijacking.c
move /y dllcomhijacking.obj dllcomhijacking.o

