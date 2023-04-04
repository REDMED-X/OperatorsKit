@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc enumlocalcert.c
move /y enumlocalcert.obj enumlocalcert.o


