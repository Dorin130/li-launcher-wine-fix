version.dll: version.c version.def
	i686-w64-mingw32-gcc -shared -o version.dll version.c version.def -s

clean:
	rm -f version.dll

.PHONY: clean
