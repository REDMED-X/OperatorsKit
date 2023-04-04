@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc dellocalcert.c
move /y dellocalcert.obj dellocalcert.o
