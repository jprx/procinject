all : injection.so target

injection.so : injection.c
	gcc -g -shared -fPIC injection.h userpref.h injection.c -o injection.so -ldl -lfunchook

target : target.c
	gcc target.c -o target
	
clean:
	rm target injection.so
