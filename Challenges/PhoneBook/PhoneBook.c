/*
 @Author : Static
 @Created Time : 2024-03-04 20:20:36
 @Description : 
*/

#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<string.h>

struct someone{
	unsigned long index;
	char name[0x10];
	char phone_number[0x8];
	struct someone* next;
};

struct someone* chunklist = NULL;

void my_read(char* buf, unsigned int size)
{
	int len = read(0, buf, size);
	if(*(buf + len - 1) == '\n')
		*(buf + len - 1) = 0;
}

struct someone* new_people(unsigned long index)
{
	struct someone* p = malloc(sizeof(struct someone));
        if(!p)
        {
                puts("Malloc error!");
                exit(0);
        }
	memset(p, 0, sizeof(struct someone));
        p->index = index;
        strcpy(p->name, "0");
        strcpy(p->phone_number, "0");
        p->next = NULL;
	return p;
}

void add()
{
	struct someone* p = chunklist;
	while(p->next)
		p = p->next;
	if(p->index >= 0x40)
	{
		puts("You can not add more!");
		return;
	}

	unsigned long index = p->index + 1;
	p->next = new_people(index);
	p = p->next;
	puts("Name?");
	my_read(p->name, 15);
	puts("Phone Number?");
	my_read(p->phone_number, 11);
	puts("Add success!\n");
}

void delete()
{
	unsigned long index = 0;
	puts("Index?");
	scanf("%lu", &index);
	if(index == 0 || index >= 0x40 )
	{
		puts("You can not delete it.");
		return;
	}

	struct someone* p = chunklist;
	struct someone* s = NULL;
	while(p->next != NULL)
	{
		s = p->next;
		if(index == s->index)
		{
			p->next = s->next;
			free(s);
			puts("Delete success!\n");
			return;
		}

		p = p->next;
	}
	puts("Index not found.");
}

void show()
{
	struct someone* p = chunklist;
	printf("%-8s%-16s%s\n", "Index", "Name", "Phone-Number");
	while(p)
	{
		printf("%-8lu%-16s%s\n", p->index, p->name, p->phone_number);
		p = p->next;
	}
	puts("Show success!\n");
}

void edit()
{
	unsigned long index = 0;
        puts("Index?");
        scanf("%lu", &index);
        if(index == 0 || index >= 0x40)
        {
                puts("You can not edit it.");
                return;
        }

	struct someone* p = chunklist;
        struct someone* s = NULL;
        while(p->next != NULL)
        {
                s = p->next;
                if(index == s->index)
                {
			puts("New Name?");
                        my_read(s->name, 15);
			puts("New Phone Number?");
			my_read(s->phone_number, 11);
                        puts("Edit success!\n");
                        return;
                }
                p = p->next;
        }
	puts("Index not found!\n");
}

void menu()
{
	puts("1. Add");
	puts("2. Delete");
	puts("3. Show");
	puts("4. Edit");
	puts("5. Exit");
	puts("Your Choice: ");
}

void init()
{
	setvbuf(stdin,0,_IONBF,0);
    	setvbuf(stdout,0,_IONBF,0);
    	setvbuf(stderr,0,_IONBF,0);
	chunklist = new_people(0);
}

int main()
{
	init();
	puts("Welcome to minilctf2024!");
        puts("Here is a simple Phone book.");
        puts("But it's so vulnerable.");

	int choice = 0;
	while(1)
	{
		menu();
		scanf("%d", &choice);
		switch(choice)
		{
			case 1: add(); break;
			case 2: delete(); break;
			case 3: show(); break;
			case 4: edit(); break;
			case 5: puts("Bye Bye! "); exit(0);
			default: puts("Unknown choice! \n"); break;
		}
	}
	return 0;
}
