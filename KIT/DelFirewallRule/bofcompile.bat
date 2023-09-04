@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc delfirewallrule.c
move /y delfirewallrule.obj delfirewallrule.o
