all : injection.so target

injection.so : injection.c
	gcc -g -shared -fPIC injection.c -o injection.so -ldl -lfunchook

target : target.c
	gcc target.c -o target -lfunchook
	
clean:
	rm target injection.so
