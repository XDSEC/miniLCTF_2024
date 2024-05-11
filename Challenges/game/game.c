/*
 @Author : Static
 @Created Time : 2024-04-19 11:55:37
 @Description : 
*/
//How to compile: gcc game.c -o game -lcurses

#include<stdio.h>
#include<stdlib.h>
#include<time.h>
#include<string.h>
#include<unistd.h>
#include<curses.h>        //  for getch() equivalent in linux 
#include"getchInLinux.h"  // contain definition of getch() equivalent in linux i.e

#define clear_screen() printf("\e[1;1H\e[2J")

int WIN = 0;
int zero_pos = 15;

void init()
{
    	setvbuf(stdin,0,_IONBF,0);
    	setvbuf(stdout,0,_IONBF,0);
    	setvbuf(stderr,0,_IONBF,0);
}

// Reads the user input character and return ascii value of that
int read_entered_key()  
{
	char c;
	c = getchInLinux();
	if(c==27 || c==91)       // this is just for scan code 
	{  
		c = getchInLinux();
		if(c==27 || c==91)     // also for scan code 
			c=getchInLinux();
	}
	return c;
}

void game_rule()
{
	clear_screen();
	printf("-----------------RULE OF THIS GAME----------------\n");
	printf("\n1. You can move only 1 step at a time by arrow key ");
	printf("\n 'w' : Move Up ");
	printf("\n 's' : Move Down ");
	printf("\n 'a' : Move Left ");
	printf("\n 'd' : Move Right ");

	printf("\n2. You can move number at empty position only \n");
	printf("\n3. For each vaild move : your total number of move will decreased by 1 \n");
	printf("\n4. Winning situation : number in a 4*4 matrix should be in order from 1 to 15 \n");
	printf(" winning situation:\n\n");
	
	int i, j, k=0;
	for(i = 0; i < 4; i++)
	{
		printf("༏  ");
		for(j = 0; j < 4; j++)
		{
			k++;
			if(k != 16)
				printf("%-3d ༏ ", k);
			else
				printf("    ༏ ");	
		}
		printf("\n");
	}

	printf("\n5. You can exit the game at any time by pressing 'E' or 'e' \n");
	printf("\nHappy Gaming, Good Luck.\n");
	printf("\nEnter any key to start......   ");
	
	read_entered_key();
}

void create_matrix(char arr[][4])
{
	int n=15;
	int num[n],i,j;
	for(i=0;i<15;i++)        // These 1-15 number will be in th matrix
		num[i]=i+1;

	srand(time(NULL));           // for random number generation

	int lastIndex=n-1,index;

	for(i=0;i<4;i++)
		for(j=0;j<4;j++)
		{  
			if(lastIndex>=0)
			{  
				index=rand()%(lastIndex+1); // idea : performing % operation by (lastIndex+1) 
				arr[i][j]=(char)num[index];       // will give index , so put that num[index] number in matrix
				num[index]=num[lastIndex--]; // and replace last number with this indexed positioned number 
			}                               // and finally lastIndex--  
		}
	arr[i-1][j-1]=0;      
}

void show_matrix(char arr[][4])
{
	int i,j;
	printf("--------------------------\n");
	for(i=0;i<4;i++)
	{ 
		printf("༏  ");
		for(j=0;j<4;j++)
		{   
			if(arr[i][j]!=0)
				printf("%-3d ༏ ",(int)arr[i][j]);
			else
				printf("    ༏ ");
		}
		printf("\n");
	}
	printf("--------------------------\n");
}

int winner(char arr[][4])
{
	int i,j,k=1;
	for(i=0;i<4;i++)
	{ 
		for(j=0;j<4;j++,k++)
			if((int)arr[i][j]!=k && k!=16)
				break;
		if(j<4)
			break;
	}
	if(j<4)
		return 0;
	WIN = 1;
	return 1;
}

// swap function to swap two numbers 
void swap(char *x, char *y)
{
	*x=*x+*y;
	*y=*x-*y;
	*x=*x-*y;
	printf("\a\a\a");
}

int shift_up(char arr[][4])
{
	int x = zero_pos / 4;
	int y = zero_pos % 4;
	swap(&arr[x][y], &arr[x-1][y]);
	zero_pos -= 4;
	return 1;
}

int shift_down(char arr[][4])
{
	int x = zero_pos / 4;
        int y = zero_pos % 4;
        swap(&arr[x][y], &arr[x+1][y]);
	zero_pos += 4;
	return 1;
}

int shift_left(char arr[][4])
{
	int x = zero_pos / 4;
        int y = zero_pos % 4;
	if(y == 0)
		return 0;
	swap(&arr[x][y], &arr[x][y-1]);
	zero_pos -= 1;
	return 1;
}

int shift_right(char arr[][4])
{
	int x = zero_pos / 4;
        int y = zero_pos % 4;
        if(y == 3)
                return 0;
        swap(&arr[x][y], &arr[x][y+1]);
        zero_pos += 1;
        return 1;
}

void backdoor()
{
	printf("Backdoor for you!\n");
	system("/bin/sh");
}

void game()
{
	char arr[4][4];
	unsigned int maxTry = 10;

	game_rule();
	create_matrix(arr);

	while(!winner(arr))	
	{
		clear_screen();
		printf("\n\nMove remaining : %u\n\n", maxTry);
		show_matrix(arr);

		if(!maxTry)
                        break;

		int key = read_entered_key();
		switch(key)
		{
			case 'w':
				if(shift_up(arr))
					maxTry--;
				break;
			case 's':
				if(shift_down(arr))
					maxTry--;
				break;
			case 'a':
				if(shift_left(arr))
					maxTry--;
				break;
			case 'd':
				if(shift_right(arr))
					maxTry--;
				break;
			case 'E':
                        case 'e':
                                printf("\a\a\a\a\nThanks for Playing !    \n\n");
                                exit(0);
			default:
				printf("\n\n[X] Not allowed     \n\n");
		}
	}
	
	return;
}

int main()
{
	char name[20];
	
	init();
	printf("Welcome to minilctf 2024!\n");
	printf("Let's play a easy game.\n");
	printf("Input your name: ");
	scanf("%20s", name);
	getchar();

	printf("Welcome %s, enjoy this game.", name);
	printf("\nEnter any key to start......   ");
        read_entered_key();

	game();

	if(WIN)
                printf("\n\n[*] You win!    \n\n");
        else
                printf("\n\n[*] You lose !     \n\n");

	return 0;
}
