# the library's version
VERSION:=0.3.0

# tools

SHELL = /bin/sh
MKDIR = mkdir
DOXYGEN= :

top_builddir = ..

DISTDIR?=$(top_builddir)/tinydtls-0.3.0
FILES:=Makefile.in Doxyfile.in html

doc:	Doxyfile
	$(DOXYGEN) $< >./doxygen.out 2>&1 

clean:
	@rm -rf html

distclean:	clean
	@rm -rf $(DISTDIR)
	@rm -f *~ 

dist:	doc
	test -d $(DISTDIR)/doc || mkdir $(DISTDIR)/doc
	cp -r $(FILES) $(DISTDIR)/doc
