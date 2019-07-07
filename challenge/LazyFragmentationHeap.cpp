// LazyFragmentationHeap.cpp : This file contains the 'main' function. Program execution begins and ends there.
//


#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <io.h>
#define MAX 10
#define MAGIC 0xddaabeef1acd

FILE* fp = NULL;
unsigned int freecount = 0;
struct fdata {
	size_t magic2;
	size_t size;
	size_t id;
	size_t magic;
	char* content;
};


//struct fdata filebuffer[MAX];
struct fdata* filebuffer = NULL;

void read_input(char* buf, unsigned int size) {
	int ret;
	ret = _read(0, buf, size);
	if (ret <= 0) {
		puts("read error");
		_exit(1);
	}
}

long long read_long() {
	char buf[24];
	long long choice;
	_read(0, buf, 23);
	choice = atoll(buf);
	return choice;
}

void menu() {
	puts("*****************************");
	puts("    LazyFragmentationHeap    ");
	puts("*****************************");
	puts(" 1. Allocate buffer for File ");
	puts(" 2. Edit File content");
	puts(" 3. Show content ");
	puts(" 4. Clean content ");
	puts(" 5. LazyFileHandler");
	puts(" 6. Exit");
	puts("****************************");
	printf("Your choice: ");
}

void filereader() {
	puts("=============================");
	puts("      Lazy File Handler      ");
	puts("=============================");
	puts(" 1. OpenFile                 ");
	puts(" 2. ReadFile                 ");
	puts(" 3. Back                     ");
	puts("=============================");
	printf("Your choice: ");
}

void initproc() {
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
//	filebuffer = (struct fdata*)calloc(MAX*2,sizeof(struct fdata));
	filebuffer = (struct fdata*)VirtualAlloc((void *)0xbeefdad0000, 0x1000, MEM_COMMIT| MEM_RESERVE, PAGE_READWRITE) ;

}

void allocate() {
	size_t size = 0;
	size_t id = 0;
	int i = 0;
	for (i = 0; i < MAX; i++) {
		if (!filebuffer[i].content) {
			printf("Size:");
			size = read_long();
			if (size > 0x2000 || size < 0x80) {
				puts("Invalid size !");
				return;
			}
			filebuffer[i].content = (char*)calloc(1, size);
			if (!filebuffer[i].content) {
				exit(-1);
			}
			filebuffer[i].magic2 = MAGIC;
			filebuffer[i].magic = MAGIC;
			filebuffer[i].size = size;
			printf("ID:");
			id = read_long();
			if (id == 0)
				id = 0xddaa;
			filebuffer[i].id = id;
			puts("Done !");
			break;
		}
	}

}

void editfile() {
	size_t idx = 0;
	size_t size = 0;
	int i = 0;
	printf("ID:");
	idx = read_long();
	if (idx == 0) {
		puts("Invalid ID !");
		return;
	}
	for (i = 0; i < MAX; i++) {
		if (filebuffer[i].id == idx) {
			if (filebuffer[i].content && (filebuffer[i].magic == MAGIC) && filebuffer[i].magic2 == MAGIC) {
				printf("Content:");
				if ((strlen(filebuffer[i].content) > filebuffer[i].size) && filebuffer[i].magic == MAGIC) {
					size = strlen(filebuffer[i].content);
				}
				else {
					size = filebuffer[i].size;
				}
				read_input(filebuffer[i].content, size);
				filebuffer[i].magic ^= 0xfaceb00ca4daddaa;
				puts("Done !");
				return;
			}
			else {
				puts("Error !");
				exit(-3);
			}

		}

	}
	if (i == MAX) {
		puts("No such file!");
		return;
	}

}



void showfile() {
	unsigned long idx = 0;
	int i = 0;
	printf("ID:");
	idx = read_long();
	if (idx == 0) {
		puts("Invalid ID !");
		return;
	}
	for (i = 0; i < MAX; i++) {
		if (filebuffer[i].id == idx) {
			if (filebuffer[i].content && filebuffer[i].magic2 == MAGIC && (filebuffer[i].magic == MAGIC || filebuffer[i].magic == (MAGIC ^ 0xfaceb00ca4daddaa) )) {
				printf("Content: %s\n", filebuffer[i].content);
				return;
			}
			else {
				puts("Error !");
				exit(-4);
			}

		}

	}
	if (i == MAX) {
		puts("No such file!");
		return;
	}

}

void openfile() {
	fopen_s(&fp, "magic.txt", "rb");
	if (fp)
		puts("Good ");
	else
		puts("Bad :(");
	return;
}

void readfile() {
	size_t size = 0;
	unsigned long idx = 0;
	int i = 0;

	if (fp) {
		printf("ID:");
		idx = read_long();
		if (idx == 0) {
			puts("Invalid ID !");
			return;
		}
		for (i = 0; i < MAX; i++) {
			if (filebuffer[i].id == idx) {
				if (filebuffer[i].content && filebuffer[i].magic == MAGIC && filebuffer[i].magic2 == MAGIC) {
					printf("Size:");
					size = read_long();
					if (size > filebuffer[i].size) {
						puts("Error !");
						exit(-1);
					}
					fread_s(filebuffer[i].content, size, 1, size, fp);
					puts("Done !");
					return;
				}
				else {
					puts("Error !");
					exit(-4);
				}

			}

		}
		if (i == MAX) {
			puts("No such filebuffer!");
			return;
		}
	
	}

}

void LazyFileHandler(unsigned int *count) {
	while (1) {
		filereader();
		switch (read_long()) {
		case 1:
			openfile();
			break;
		case 2:
			if (*count >= 2) {
				puts("you can not read more !");
				break;
			}
			readfile();
			(*count)++;
			break;
		case 3:
			return;
			break;
		default:
			puts("Invalid choice");
			break;
		}
	}

}

void clearcontent() {
	unsigned long idx = 0 ;
	printf("ID:");
	idx = read_long();
	if (idx == 0) {
		puts("Invalid ID !");
		return;
	}
	int i = 0;
	for (i = 0; i < MAX; i++) {
		if (filebuffer[i].id == idx && freecount < 2) {
			if (filebuffer[i].content && filebuffer[i].magic2 == MAGIC) {
				freecount++;
				free(filebuffer[i].content);
				filebuffer[i].content = NULL;
				filebuffer[i].magic2 = 0;
				filebuffer[i].id = 0;
				filebuffer[i].magic = 0;
				filebuffer[i].size = 0;
				return;
			}
			else {
				puts("Error !");
				exit(-4);
			}

		}

	}
	if (i == MAX) {
		puts("No such file!");
		return;
	}

}

int main()
{
	unsigned int count = 0;
	
	initproc();
	while (1) {
		menu();
		switch (read_long()) {
		case 1:
			allocate();
			break;
		case 2:
			editfile();
			break;
		case 3:
			showfile();
			break;
		case 4:
			clearcontent();
			break;
		case 5:	
			LazyFileHandler(&count);
			break;
		case 6:
			exit(0);
			break;
		default:
			puts("Invalid choice");
			break;
		}
	}
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
