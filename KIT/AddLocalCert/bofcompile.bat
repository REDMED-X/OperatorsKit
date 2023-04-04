@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc addlocalcert.c
move /y addlocalcert.obj addlocalcert.o


