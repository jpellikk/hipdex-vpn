/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <getopt.h>
#include <inttypes.h>
#include <errno.h>

#include "Exception.h"
#include "Daemon.h"
#include "Defines.h"
#include "Types.h"

using namespace hipdex_vpn;

static TUserOptions s_userOpt = { false, false, LogLevel::Warning, "" };

static const char* s_optionHelp[] = {
	"Run as daemon (and forward output to syslog)",
	"Forward output to syslog instead of stdout",
	"Set the verbosity of output (1-4; default 2)",
	"Store the program output to a text file",
	"Print version information and exit",
	"Print this help dialog and exit"
};

static const option s_options[] = {
	{ "daemon",        0,   NULL,   'd' },
	{ "syslog",        0,   NULL,   's' },
	{ "verbosity",     1,   NULL,   'l' },
	{ "output",        1,   NULL,   'o' },
	{ "version",       0,   NULL,   'v' },
	{ "help",          0,   NULL,   'h' },
	{ NULL, 0, NULL, 0}
};

void printUsageInfo(const char* appName)
{
	fprintf(stdout, "Usage: %s [OPTIONS]\nOptions:\n", appName);

	for (int i = 0; s_options[i].name; ++i)
	{
		if (s_optionHelp[i] == NULL)
			continue;

		char buf[40];
		const char *arg_str;

		switch (s_options[i].has_arg)
		{
			case 1:
				arg_str = " <arg>";
				break;
			case 2:
				arg_str = " [arg]";
				break;
			default:
				arg_str = "";
				break;
		}

		if (isprint(s_options[i].val) && !isspace(s_options[i].val))
			snprintf(buf, sizeof buf, "-%c, --%s%s", s_options[i].val,
				s_options[i].name, arg_str);
		else
			snprintf(buf, sizeof buf, "    --%s%s", s_options[i].name, arg_str);

		fprintf(stdout, "  %-28s  %s\n", buf, s_optionHelp[i]);
	}
}

void daemonize()
{
	if (getppid() == 1) {
		return;
	}

	int p = fork();

	if (p < 0) {
		exit(EXIT_FAILURE);
	}

	if (p > 0) {
		exit(EXIT_SUCCESS);
	}

	setsid();

	for (p = getdtablesize(); p >= 0; --p) {
		close(p);
	}

	p = open("/dev/null", O_RDWR);

	if (dup(p) < 0) {
		exit(EXIT_FAILURE);
	}

	if (dup(p) < 0) {
		exit(EXIT_FAILURE);
	}

	umask(027);

	if (chdir(HDX_DAEMON_RUNNING_DIR) < 0) {
		exit(EXIT_FAILURE);
	}

	int fp = open(HDX_DAEMON_LOCK_FILE, O_RDWR|O_CREAT, 0640);

	if (fp < 0) {
		exit(EXIT_FAILURE);
	}

	if (lockf(fp, F_TLOCK, 0) < 0) {
		exit(EXIT_SUCCESS);
	}

	char pid[10];
	sprintf(pid, "%d\n", getpid());

	if (write(fp, pid, strlen(pid)) < 0) {
		exit(EXIT_FAILURE);
	}

	signal(SIGCHLD, SIG_IGN);
	signal(SIGTSTP, SIG_IGN);
	signal(SIGTTOU, SIG_IGN);
	signal(SIGTTIN, SIG_IGN);

	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
}

void processArguments(int argc, char** argv, TUserOptions& options)
{
	int opt, long_optind = 0;

	while ((opt = getopt_long(argc, argv, "vhdsl:o:", s_options, &long_optind)) != -1)
	{
		switch (opt)
		{
			case 'd':
				options.m_daemonMode = true;
				options.m_printToSyslog = true;
				break;
			case 's':
				options.m_printToSyslog = true;
				break;
			case 'l': {
				uintmax_t num = strtoumax(optarg, NULL, 10);
				LogLevel::Type levels[4] = {
					LogLevel::Error,
					LogLevel::Warning,
					LogLevel::Info,
					LogLevel::Debug
				};
				if (num > 0 && num < 5 && errno == 0) {
					options.m_logLevel = levels[num - 1];
					break;
				}
				fprintf(stderr, "%s: invalid verbosity level: %s\n", argv[0], optarg);
				exit(EXIT_FAILURE);
				break;
			}
			case 'o': {
				if (strlen(optarg) < sizeof options.m_fileName) {
					strcpy(options.m_fileName, optarg);
					break;
				}
				fprintf(stderr, "%s: invalid file name: name too long\n", argv[0]);
				exit(EXIT_FAILURE);
				break;
			}
			case 'v':
				fprintf(stdout, "%s\n", PACKAGE_STRING);
				exit(EXIT_SUCCESS);
				break;
			case 'h':
				printUsageInfo(argv[0]);
				exit(EXIT_SUCCESS);
				break;
			case ':':
			case '?':
			default:
				fprintf(stderr, "Try `%s --help' for more information.\n", argv[0]);
				exit(EXIT_FAILURE);
		}
	}
}

int main(int argc, char** argv)
{
	processArguments(argc, argv, s_userOpt);

	LOGGER_SET_LEVEL((LogLevel::Type)
		s_userOpt.m_logLevel);

	if (s_userOpt.m_daemonMode)
		daemonize();

	if (s_userOpt.m_printToSyslog)
		LOGGER_SYSLOG(argv[0]);
	else
		LOGGER_STDOUT();

	try
	{
		if (strlen(s_userOpt.m_fileName) > 0)
			LOGGER_FILE(s_userOpt.m_fileName);

		Daemon daemon(s_userOpt);
		daemon.Run();
	}
	catch (Exception& exception)
	{
		LOGGER_ERROR(exception.GetWhat());
		LOGGER_ERROR("Program terminated.");

		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
