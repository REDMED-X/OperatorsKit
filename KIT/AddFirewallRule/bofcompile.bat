@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc addfirewallrule.c
move /y addfirewallrule.obj addfirewallrule.o

