/*-------------------------------------------------------------------------
 *
 * alertseverity.c
 *
 * Set the severity level of the alert based on the message
 *
 * Copyright (c) 2010, EMC Corporation
 *
 *
 *-------------------------------------------------------------------------
 */
#if !defined(_XOPEN_SOURCE) || _XOPEN_SOURCE<600
#undef _XOPEN_SOURCE
#define _XOPEN_SOURCE 600
#endif
#if !defined(_POSIX_C_SOURCE) || _POSIX_C_SOURCE<200112L
#undef _POSIX_C_SOURCE
/* Define to activate features from IEEE Stds 1003.1-2001 */
#define _POSIX_C_SOURCE 200112L
#endif
#include "postgres.h"
#include "pg_config.h"  /* todo: is this necessary? */

#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <stdio.h>

#include "lib/stringinfo.h"

#include "pgtime.h"

#include "postmaster/syslogger.h"
#include "postmaster/sendalert.h"
#include "utils/guc.h"
#include "utils/elog.h"
#include "utils/builtins.h"
#include "sendalert_common.h"



int set_alert_severity(const GpErrorData * errorData, 
						char *subject,
						bool *send_via_email,
						char *email_priority)
						
{

	/*
	 * Set up the primary alert message
	 *
	 */
	if (strcmp(errorData->error_severity,"LOG") == 0)
		snprintf(subject, MAX_ALERT_STRING, "%s",errorData->error_message);
	else if (errorData->sql_state && strcmp(errorData->sql_state,"57P03") == 0)
		snprintf(subject, MAX_ALERT_STRING, "%s",errorData->error_message);
	else
		snprintf(subject, MAX_ALERT_STRING, "%s: %s",errorData->error_severity, errorData->error_message);
	subject[MAX_ALERT_STRING] = '\0'; /* Guarantee subject is zero terminated */

	
	/*
	// ERRCODE_DISK_FULL could be reported vi rbmsMIB rdbmsTraps rdbmsOutOfSpace trap.
	// But it appears we never generate that error?

	// ERRCODE_ADMIN_SHUTDOWN means SysAdmin aborted somebody's request.  Not interesting?

	// ERRCODE_CRASH_SHUTDOWN sounds interesting, but I don't see that we ever generate it.

	// ERRCODE_CANNOT_CONNECT_NOW means we are starting up, shutting down, in recovery, or Too many users are logged on.

	// abnormal database system shutdown
	*/

	*send_via_email = true;

	email_priority[0] = '3';		// normal priority
	email_priority[1] = '\0';
	
	/*
	 * Check for "Interesting" messages.
	 * Use of gettext() is because the strings are already localized in the errorData structure.
	 */
	if (strstr(errorData->error_message, gettext("abnormal database system shutdown")) != NULL ||
		strstr(errorData->error_message, gettext("the database system is shutting down"))  != NULL ||
		strstr(errorData->error_message, gettext("received smart shutdown request")) != NULL ||
		strstr(errorData->error_message, gettext("received fast shutdown request")) != NULL ||
		strstr(errorData->error_message, gettext("received immediate shutdown request")) != NULL ||
		strstr(errorData->error_message, gettext("database system is shut down"))  != NULL)
	{
		email_priority[0] = '1'; // 1 == highest priority
	}
	else if (strstr(errorData->error_message, gettext("Master mirroring synchronization lost"))  != NULL ||
			  strstr(errorData->error_message, gettext("Error from sending to standby master"))  != NULL ||
			  strstr(errorData->error_message, gettext("error received sending data to standby master"))  != NULL ||
			  strstr(errorData->error_message, gettext("is going into change tracking mode"))  != NULL ||
			  strstr(errorData->error_message, gettext("is taking over as primary in change tracking mode"))  != NULL ||
			  strstr(errorData->error_message, "GPDB performed segment reconfiguration.") != NULL) // elog, so no gettext
	{
		email_priority[0] = '1';
	}

	else if (strstr(errorData->error_message, gettext("the database system is starting up")) != NULL)
	{
		email_priority[0] = '5'; // 5  == lowest priority
	}

	else if (strstr(errorData->error_message, gettext("database system is ready to accept connections"))  != NULL)
	{
		email_priority[0] = '5'; // lowest
	}

	else if (strstr(errorData->error_message, gettext("could not access status of transaction"))  != NULL)
	{
		/* This error usually means a table has been corrupted.  Should it be a 4? 5? 6? 7?*/
		email_priority[0] = '1'; /// 1 == highest priority
	}

	else if (strstr(errorData->error_message, gettext("database system was interrupted while in recovery"))  != NULL)
	{
		/* This error usually means the entire database is questionable, and should be restored from backup  */
		email_priority[0] = '1'; // 1 == highest priority
	}

	else if (strstr(errorData->error_message, gettext("two-phase state file for transaction"))  != NULL &&
			 strstr(errorData->error_message, gettext("corrupt"))  != NULL)
	{
		email_priority[0] = '1'; // 1 == highest priority
	}

	else if (strstr(errorData->error_message, "Test message for Connect EMC")  != NULL)
	{
		email_priority[0] = '5'; // 5  == lowest priority
	}

	else if (strcmp(errorData->error_severity,gettext("PANIC")) == 0)
	{
		email_priority[0] = '1'; // 1 == highest priority
	}

	return 0;
}



	
