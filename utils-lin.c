/**
 * Operating Sytems 2013 - Assignment 1
 *
 */

#include <assert.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>

#include "utils.h"

#define READ		0
#define WRITE		1


/**
 * Internal exit/quit command.
 */
static int shell_exit()
{
	/* TODO execute exit/quit */
	exit(0);
	return 0; /* TODO replace with actual exit code */
}

/**
 * Concatenate parts of the word to obtain the command
 */
static char *get_word(word_t *s)
{
	int string_length = 0;
	int substring_length = 0;

	char *string = NULL;
	char *substring = NULL;

	while (s != NULL) {
		substring = strdup(s->string);

		if (substring == NULL) {
			return NULL;
		}

		if (s->expand == true) {
			char *aux = substring;
			substring = getenv(substring);

			/* prevents strlen from failing */
			if (substring == NULL) {
				substring = calloc(1, sizeof(char));
				if (substring == NULL) {
					free(aux);
					return NULL;
				}
			}

			free(aux);
		}

		substring_length = strlen(substring);

		string = realloc(string, string_length + substring_length + 1);
		if (string == NULL) {
			if (substring != NULL)
				free(substring);
			return NULL;
		}

		memset(string + string_length, 0, substring_length + 1);

		strcat(string, substring);
		string_length += substring_length;

		if (s->expand == false) {
			free(substring);
		}

		s = s->next_part;
	}

	return string;
}

/**
 * Concatenate command arguments in a NULL terminated list in order to pass
 * them directly to execv.
 */
static char **get_argv(simple_command_t *command, int *size)
{
	char **argv;
	word_t *param;

	int argc = 0;
	argv = calloc(argc + 1, sizeof(char *));
	assert(argv != NULL);

	argv[argc] = get_word(command->verb);
	assert(argv[argc] != NULL);

	argc++;

	param = command->params;
	while (param != NULL) {
		argv = realloc(argv, (argc + 1) * sizeof(char *));
		assert(argv != NULL);

		argv[argc] = get_word(param);
		assert(argv[argc] != NULL);

		param = param->next_word;
		argc++;
	}

	argv = realloc(argv, (argc + 1) * sizeof(char *));
	assert(argv != NULL);

	argv[argc] = NULL;
	*size = argc;

	return argv;
}


/**
 * \param word - cuvantul care trebuie xpandat
 */
static char* expand(word_t *word)
{
	char* expand = (char*)malloc(sizeof(char) * 100);
	strcpy(expand, "");
	expand[0] = 0;
	word_t *it = word;
	while(it){
		if(it->expand){
			char* tmp_c = getenv(it->string);
			if(tmp_c){
				strcat(expand, tmp_c);
			}
		}
		else{
			strcat(expand, it->string);
		}
		it = it->next_part;
	}
	return expand;
}

/**
 * \param s - comanda ce trebuie executata
 * \param father  - parintele comenzii
 * \param pid - pid-ul procesului curent
 */
static pid_t exec_process(simple_command_t *s, command_t *father, pid_t pid)
{
	word_t *param = s->params;
    unsigned int i, size;
	char** args = get_argv(s, &size);

	param = s->params;
	for(i = 1; i < size; ++i){
			args[i] = expand(param);
			param = param->next_word;
	}
    
    if(pid == 0){
    	int fd;
    	int tmp_t = 0;
    	while(s->out){
    		char* expanded = expand(s->out);
    		if(s->io_flags == IO_REGULAR){
    			if(s->err != NULL){
    				unlink(s->out->string);
    				fd = open(expanded, O_WRONLY | O_CREAT | O_APPEND, 0644);
    			}
    			else
    				fd = open(expanded, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    			tmp_t = 1;
    		}

    		if(s->io_flags == IO_OUT_APPEND){
    			fd = open(expanded, O_WRONLY | O_CREAT | O_APPEND, 0644);
    		}

    		dup2(fd, STDOUT_FILENO);
    		close(fd);

    		s->out = s->out->next_word;
    	}
    	while(s->in){
    		char* expanded = expand(s->in);
    		fd = open(expanded, O_RDONLY, 0644);
    		dup2(fd, STDIN_FILENO);
    		close(fd);
    		s->in = s->in->next_word;
    	}

    	while(s->err){
    		char* expanded = expand(s->err);
    		if(s->io_flags != 0){
    			fd = open(expanded, O_WRONLY | O_CREAT | O_APPEND, 0644);
    		}
    		else{
    			if(tmp_t == 1){
    				fd = open(expanded, O_WRONLY | O_CREAT | O_APPEND, 0644);
    			}
    			else{
    				fd = open(expanded, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    			}
    		}
    		dup2(fd, STDERR_FILENO);
    		close(fd);
    		s->err = s->err->next_word;
    	}
    	int size;
    	if(execvp(s->verb->string, args) == -1){
    		printf("Execution failed for '%s'\n", s->verb->string);
    		exit(-1);
    	}
    }
}


/**
 * \param s - comanda simpla pentru care trebuie pornit procesul
 * \param father - parintele comenzii
 */
static pid_t startProcess(simple_command_t *s, command_t *father)
{
	pid_t pid = fork();
	if(pid == 0)
    	exec_process(s, father, pid);
    return pid;
}

/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */
static int parse_simple(simple_command_t *s, command_t *father)
{
	/* TODO sanity checks */
	if(s == NULL)
		return -1;
	/* TODO if builtin command, execute the command */

	/* TODO if variable assignment, execute the assignment and return
         * the exit status */
	
	if(s->verb->next_part != NULL){
		setenv(s->verb->string, s->verb->next_part->next_part->string, 1);
		return 0;
	}
	
	/* TODO if external command:
         *   1. fork new process
	 *     2c. perform redirections in child
         *     3c. load executable in child
         *   2. wait for child
         *   3. return exit status
	 */
    pid_t pid = startProcess(s, father);
    int status;
    if(pid != 0){
    	wait(&status);
    }
	return status; 
}


/**
 * Process two commands in parallel, by creating two children.
 */
static bool do_in_parallel(command_t *cmd, command_t *father)
{
	int status;
	pid_t pid = -1;
	/* TODO execute cmd1 and cmd2 simultaneously */
	if(cmd->scmd != NULL){
		pid = startProcess(cmd->scmd, father);
	}
	else{
		if(cmd->op == OP_PARALLEL){
			pid_t pid_1 = fork();
			if(pid_1 == 0){
				do_in_parallel(cmd->cmd1, cmd);
			}
			else{
				pid_t pid_2 = fork();
				if(pid_2 == 0){
					do_in_parallel(cmd->cmd2, cmd);
				}
			}
		}
		else{
			parse_command(cmd, cmd->up);
		}
	}
	return true; 
}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2)
 * \param cmd  - comanda ce trebuie executata
 * \param father - parintele comenzii
 * \param queue  - coada in care sunt pastrate comenzile la intoarcerea din stiva
 * \param  queue_len - lungimea cozii
 */
static bool do_on_pipe(command_t *cmd, command_t *father, simple_command_t *queue[100], unsigned int *queue_len)
{
	/* TODO redirect the output of cmd1 to the input of cmd2 */
	if(!cmd)
		return true;
	if(cmd->scmd){
		queue[*queue_len] = cmd->scmd;
		(*queue_len)++;
		return true;
	}
	//printf("%d\n", queue_len);
	if(cmd->cmd1 != NULL){
		do_on_pipe(cmd->cmd1, cmd, queue, queue_len);
	}

	if(cmd->cmd2 != NULL){
		do_on_pipe(cmd->cmd2, cmd, queue, queue_len);
	}

	
	if(father == NULL || father->op != OP_PIPE){
		int fdes[(*queue_len)-1][2];
		int i; 
		for(i = 0; i < (*queue_len) - 1 ; i++){
			pipe(fdes[i]);
		}

		pid_t pid = fork();
		if(pid == 0){
			dup2(fdes[0][1], STDOUT_FILENO);
			exec_process(queue[0], father, pid);
		
		}
		close(fdes[0][1]);

		for(i = 1; i < (*queue_len) - 1; ++i){
			pid = fork();
			if(pid == 0){
				dup2(fdes[i-1][0], STDIN_FILENO);
				dup2(fdes[i][1], STDOUT_FILENO);
				exec_process(queue[i], father, pid);
			}
			close(fdes[i][1]);
			close(fdes[i-1][0]);
		}

		pid = fork();
		if(pid == 0){
			dup2(fdes[(*queue_len)-2][0], STDIN_FILENO);
			exec_process(queue[(*queue_len)-1], father, pid);
		}
		close(fdes[0][0]);

		return true;
	}
	

	return true; /* TODO replace with actual exit status */
}

/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, command_t *father)
{
	/* TODO sanity checks */
	if(c == NULL){
		return 0;
	}

	int status;

	if (c->op == OP_NONE) {
		/* TODO execute a simple command */
		if(strcmp(c->scmd->verb->string, "exit") == 0 || strcmp(c->scmd->verb->string, "quit") == 0){
			shell_exit();
		}

		if(strcmp(c->scmd->verb->string, "cd") == 0){
			if(c->scmd->params){
				if(chdir(c->scmd->params->string) != 0){
					int fd;
		    		if(c->scmd->io_flags == IO_REGULAR){
		    			fd = open(c->scmd->out->string, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		    		}
		    		close(fd);
					return -1;
				}
			}
			else{
				chdir("");
			}
			return 0;
		}
		return parse_simple(c->scmd, father);
		/* TODO replace with actual exit code of command */
	}

	switch (c->op) {
	case OP_SEQUENTIAL:
		parse_command(c->cmd1, father);
		return parse_command(c->cmd2, father);
		/* TODO execute the commands one after the other */
		break;

	case OP_PARALLEL:
		/* TODO execute the commands simultaneously */
		do_in_parallel(c, father);
		if(father == NULL || father->op != OP_PARALLEL){
			while(wait(NULL) > 0);
		}
		break;

	case OP_CONDITIONAL_NZERO:
		/* TODO execute the second command only if the first one
                 * returns non zero */
		if(parse_command(c->cmd1, father) != 0)
			return parse_command(c->cmd2, father);
		break;

	case OP_CONDITIONAL_ZERO:
		/* TODO execute the second command only if the first one
                 * returns zero */
		if(parse_command(c->cmd1, father) == 0)
				return parse_command(c->cmd2, father);
		break;

	case OP_PIPE:{
		simple_command_t *cmds[100];
		unsigned int x = 0;
		do_on_pipe(c, father, cmds, &x);
		while(wait(NULL) > 0);                     //astept toate procesele
		/* TODO redirect the output of the first command to the
		 * input of the second */
		break;
		return 0;
	}
	default:
		assert(false);
	}

	return 0; /* TODO replace with actual exit code of command */
}

/**
 * Readline from mini-shell.
 */
char *read_line()
{
	char *instr;
	char *chunk;
	char *ret;

	int instr_length;
	int chunk_length;

	int endline = 0;

	instr = NULL;
	instr_length = 0;

	chunk = calloc(CHUNK_SIZE, sizeof(char));
	if (chunk == NULL) {
		fprintf(stderr, ERR_ALLOCATION);
		return instr;
	}

	while (!endline) {
		ret = fgets(chunk, CHUNK_SIZE, stdin);
		if (ret == NULL) {
			break;
		}

		chunk_length = strlen(chunk);
		if (chunk[chunk_length - 1] == '\n') {
			chunk[chunk_length - 1] = 0;
			endline = 1;
		}

		ret = instr;
		instr = realloc(instr, instr_length + CHUNK_SIZE + 1);
		if (instr == NULL) {
			free(ret);
			return instr;
		}
		memset(instr + instr_length, 0, CHUNK_SIZE);
		strcat(instr, chunk);
		instr_length += chunk_length;
	}

	free(chunk);

	return instr;
}

