@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc dcomlocalserver32.c
move /y dcomlocalserver32.obj dcomlocalserver32.o

