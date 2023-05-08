@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc enumsecproducts.c
move /y enumsecproducts.obj enumsecproducts.o


