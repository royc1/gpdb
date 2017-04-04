/*-------------------------------------------------------------------------
 *
 * sendalert.c
 *	  Send alerts via SMTP (email)
 *
 * Copyright (c) 2009, Greenplum
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
#include "pg_config.h"  /* todo necessary? */

#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <stdio.h>

#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif
#include <arpa/inet.h>

#include "lib/stringinfo.h"

#include "pgtime.h"

#include "postmaster/syslogger.h"
#include "postmaster/sendalert.h"
#include "utils/guc.h"
#include "utils/elog.h"
#include "utils/builtins.h"
#include "utils/memutils.h"
#include "sendalert_common.h"

extern int	PostPortNumber;

#if defined(HAVE_DECL_CURLOPT_MAIL_FROM) && HAVE_DECL_CURLOPT_MAIL_FROM
#include <curl/curl.h>
#endif

#if defined(HAVE_DECL_CURLOPT_MAIL_FROM) && HAVE_DECL_CURLOPT_MAIL_FROM
/* state information for messagebody_cb function */
typedef struct
{
	StringInfoData body;
	size_t consumed;
} upload_ctx;

static size_t messagebody_cb(void *ptr, size_t size, size_t nmemb, void *userp);
static void build_messagebody(StringInfo buf, const GpErrorData *errorData,
				  const char *subject, const char *email_priority);

static void send_alert_via_email(const GpErrorData * errorData,
					 const char * subject, const char * email_priority);
static char *extract_email_addr(char *str);
static bool SplitMailString(char *rawstring, char delimiter, List **namelist);
#endif

int send_alert_from_chunks(const PipeProtoChunk *chunk,
		const PipeProtoChunk * saved_chunks_in)
{

	int ret = -1;
	GpErrorData errorData;

	CSVChunkStr chunkstr =
	{ chunk, chunk->data + sizeof(GpErrorDataFixFields) };

	memset(&errorData, 0, sizeof(errorData));

	memcpy(&errorData.fix_fields, chunk->data, sizeof(errorData.fix_fields));

	if (chunk == NULL)
		return -1;
	if (chunk->hdr.len == 0)
		return -1;
	if (chunk->hdr.zero != 0)
		return -1;

	if (chunk->hdr.log_format != 'c')
		elog(ERROR,"send_alert_from_chunks only works when CSV logging is enabled");

	errorData.username = get_str_from_chunk(&chunkstr,saved_chunks_in);
	errorData.databasename = get_str_from_chunk(&chunkstr,saved_chunks_in);
	errorData.remote_host = get_str_from_chunk(&chunkstr,saved_chunks_in);
	errorData.remote_port = get_str_from_chunk(&chunkstr,saved_chunks_in);
	errorData.error_severity = get_str_from_chunk(&chunkstr,saved_chunks_in);
	errorData.sql_state = get_str_from_chunk(&chunkstr,saved_chunks_in);
	errorData.error_message = get_str_from_chunk(&chunkstr,saved_chunks_in);
	errorData.error_detail = get_str_from_chunk(&chunkstr,saved_chunks_in);
	errorData.error_hint = get_str_from_chunk(&chunkstr,saved_chunks_in);
	errorData.internal_query = get_str_from_chunk(&chunkstr,saved_chunks_in);
	errorData.error_context = get_str_from_chunk(&chunkstr,saved_chunks_in);
	errorData.debug_query_string = get_str_from_chunk(&chunkstr,saved_chunks_in);
	errorData.error_func_name = get_str_from_chunk(&chunkstr,saved_chunks_in);
	errorData.error_filename = get_str_from_chunk(&chunkstr,saved_chunks_in);
	errorData.stacktrace = get_str_from_chunk(&chunkstr,saved_chunks_in);


	PG_TRY();
	{
	ret = send_alert(&errorData);
	}
	PG_CATCH();
	{
		elog(LOG,"send_alert failed.  Not sending the alert");
		free(errorData.stacktrace ); errorData.stacktrace = NULL;
		free((char *)errorData.error_filename ); errorData.error_filename = NULL;
		free((char *)errorData.error_func_name ); errorData.error_func_name = NULL;
		free(errorData.debug_query_string ); errorData.debug_query_string = NULL;
		free(errorData.error_context); errorData.error_context = NULL;
		free(errorData.internal_query ); errorData.internal_query = NULL;
		free(errorData.error_hint ); errorData.error_hint = NULL;
		free(errorData.error_detail ); errorData.error_detail = NULL;
		free(errorData.error_message ); errorData.error_message = NULL;
		free(errorData.sql_state ); errorData.sql_state = NULL;
		free((char *)errorData.error_severity ); errorData.error_severity = NULL;
		free(errorData.remote_port ); errorData.remote_port = NULL;
		free(errorData.remote_host ); errorData.remote_host = NULL;
		free(errorData.databasename ); errorData.databasename = NULL;
		free(errorData.username ); errorData.username = NULL;
		/* Carry on with error handling. */
		PG_RE_THROW();
	}
	PG_END_TRY();

	// Don't forget to free them!  Best in reverse order of the mallocs.

	free(errorData.stacktrace ); errorData.stacktrace = NULL;
	free((char *)errorData.error_filename ); errorData.error_filename = NULL;
	free((char *)errorData.error_func_name ); errorData.error_func_name = NULL;
	free(errorData.debug_query_string ); errorData.debug_query_string = NULL;
	free(errorData.error_context); errorData.error_context = NULL;
	free(errorData.internal_query ); errorData.internal_query = NULL;
	free(errorData.error_hint ); errorData.error_hint = NULL;
	free(errorData.error_detail ); errorData.error_detail = NULL;
	free(errorData.error_message ); errorData.error_message = NULL;
	free(errorData.sql_state ); errorData.sql_state = NULL;
	free((char *)errorData.error_severity ); errorData.error_severity = NULL;
	free(errorData.remote_port ); errorData.remote_port = NULL;
	free(errorData.remote_host ); errorData.remote_host = NULL;
	free(errorData.databasename ); errorData.databasename = NULL;
	free(errorData.username ); errorData.username = NULL;

	return ret;
}

#if defined(HAVE_DECL_CURLOPT_MAIL_FROM) && HAVE_DECL_CURLOPT_MAIL_FROM
static void
send_alert_via_email(const GpErrorData *errorData,
					 const char *subject, const char *email_priority)
{
	CURL	   *curl;
	upload_ctx	upload_ctx;
	char	   *rawstring;
	List	   *elemlist = NIL;
	ListCell   *l;
	static int	num_connect_failures = 0;
	static time_t last_connect_failure_ts = 0;
	char		smtp_url[200];
	int			num_recipients;
	int			num_sent_successfully;
	char	   *from = NULL;

	if (gp_email_connect_failures && num_connect_failures >= gp_email_connect_failures)
	{
		if (time(0) - last_connect_failure_ts > gp_email_connect_avoid_duration)
		{
			num_connect_failures = 0;
			elog(LOG, "Retrying emails now...");
		}
		else
		{
			elog(LOG, "Not attempting emails as of now");
			return;
		}
	}

	if (gp_email_to == NULL || strlen(gp_email_to) == 0)
	{
		static bool firsttime = 1;

		ereport(firsttime ? LOG : DEBUG1,(errmsg("e-mail alerts are disabled")));
		firsttime = false;
		return;
	}

    /*
     * Per curl docs/example:
	 *
     * Note that this option isn't strictly required, omitting it will result
     * in libcurl sending the MAIL FROM command with empty sender data. All
     * autoresponses should have an empty reverse-path, and should be directed
     * to the address in the reverse-path which triggered them. Otherwise, they
     * could cause an endless loop. See RFC 5321 Section 4.5.5 for more details.
     */
	if (strlen(gp_email_from) == 0)
	{
		elog(LOG, "e-mail alerts are not properly configured:  No 'from:' address configured");
		return;
	}

	if (strchr(gp_email_to, ';') == NULL && strchr(gp_email_to, ',') != NULL)
	{
		// email addrs should be separated by ';', but because we used to require ',',
		// let's accept that if it looks OK.
		while (strchr(gp_email_to,',') != NULL)
			*strchr(gp_email_to,',') = ';';
	}

	from = extract_email_addr(gp_email_from);

	/* Build the message headers + body */
	initStringInfo(&upload_ctx.body);
	build_messagebody(&upload_ctx.body, errorData, subject, email_priority);

	if (gp_email_smtp_server != NULL && strlen(gp_email_smtp_server) > 0)
		snprintf(smtp_url, sizeof(smtp_url), "smtp://%s", gp_email_smtp_server);
	else
		snprintf(smtp_url, sizeof(smtp_url), "smtp://localhost");

	/* Need a modifiable copy of To list */
	rawstring = pstrdup(gp_email_to);

	/* Parse string into list of identifiers */
	if (!SplitMailString(rawstring, ';', &elemlist))
	{
		/* syntax error in list */
		ereport(LOG,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("invalid list syntax for \"gp_email_to\"")));
	}

	/*
	 * Ok, let's initialize libcurl.
	 */
	curl = curl_easy_init();
	if (curl)
	{
		PG_TRY();
		{
			/*
			 * Loop around the list of recipients, and send the same message
			 * to each one. We send all the messages using the same
			 * easy-handle; that allows curl to reuse the same connection for
			 * each sent message.
			 *
			 * XXX: libcurl supports sending to a list of recipients, but if
			 * the delivery to any one of them fails, it bails out without
			 * sending to any of the recipients. See curl known bug #70,
			 * http://curl.haxx.se/bug/view.cgi?id=1116
			 *
			 * If that ever gets fixed in libcurl, we should build a single
			 * list of recipients here and only send the mail once.
			 */
			num_recipients = 0;
			num_sent_successfully = 0;
			foreach(l, elemlist)
			{
				char	   *cur_gp_email_addr = (char *) lfirst(l);
				char	   *to;
				struct curl_slist *recipient;
				bool		connect_failure = false;
				CURLcode	res;
				char		curlerror[CURL_ERROR_SIZE];

				if (cur_gp_email_addr == NULL || *cur_gp_email_addr == '\0')
					continue;
				num_recipients++;

				/* Recipient must be in RFC2821 format */
				to = extract_email_addr(cur_gp_email_addr);

				recipient = curl_slist_append(NULL, to);

				if (recipient == NULL)
				{
					elog(LOG, "could not append recipient %s", to);
					pfree(to);
					continue;
				}

				curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curlerror);
				curl_easy_setopt(curl, CURLOPT_URL, smtp_url);
				curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT,
								 (long) gp_email_connect_timeout);
				if (gp_email_smtp_userid && *gp_email_smtp_userid)
					curl_easy_setopt(curl, CURLOPT_USERNAME,
									 gp_email_smtp_userid);
				if (gp_email_smtp_password && *gp_email_smtp_password)
					curl_easy_setopt(curl, CURLOPT_PASSWORD,
									 gp_email_smtp_password);
				if (from && *from)
					curl_easy_setopt(curl, CURLOPT_MAIL_FROM, from);
				curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipient);

				/*
				 * Use a callback function to pass the payload (headers and
				 * the message body) to libcurl.
				 */
				upload_ctx.consumed = 0;
				curl_easy_setopt(curl, CURLOPT_READFUNCTION, messagebody_cb);
				curl_easy_setopt(curl, CURLOPT_READDATA, &upload_ctx);
				curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

				/* Ok, all set. Send the message */
				res = curl_easy_perform(curl);

				curl_slist_free_all(recipient);

				/* Did it succeed? */
				switch(res)
				{
					case CURLE_OK:
						num_connect_failures = 0;
						num_sent_successfully++;
						break;

						/*
						 * If we get any of these errors, something went wrong
						 * with connecting to the server. Treat it as a
						 * connection failure, and bail out immediately
						 * without trying the rest of the recipients.
						 */
					case CURLE_OPERATION_TIMEDOUT:
					case CURLE_UNSUPPORTED_PROTOCOL:
					case CURLE_URL_MALFORMAT:
					case CURLE_COULDNT_RESOLVE_PROXY:
					case CURLE_COULDNT_RESOLVE_HOST:
					case CURLE_COULDNT_CONNECT:
						ereport(LOG,
								(errmsg("could not connect to SMTP server"),
								 errdetail("%s", curlerror)));
						connect_failure = true;
						break;

						/*
						 * Any other error might be because of an invalid
						 * recipient, for example, and we might still succeed
						 * in sending to the other recipients. Continue.
						 */
					default:
						ereport(LOG,
								(errmsg("could not send alert email to \"%s\"", to),
								 errdetail("%s", curlerror)));
						break;
				}

				pfree(to);

				if (connect_failure)
					break;
			}
			if (num_recipients == 0 && list_length(elemlist) > 0)
				ereport(LOG,
						(errmsg("Could not understand e-mail To: list")));
			else if (num_sent_successfully == 0)
			{
				/*
				 * If we couldn't deliver the mail to any recipients, treat it
				 * as a connection failure.
				 */
				num_connect_failures++;
				last_connect_failure_ts = time(NULL);
			}
		}
		PG_CATCH();
		{
			/*
			 * Close the handle. This closes the connection to the SMTP
			 * server.
			 */
			curl_easy_cleanup(curl);

			PG_RE_THROW();
		}
		PG_END_TRY();

		/* Close the handle. This closes the connection to the SMTP server. */
		curl_easy_cleanup(curl);
	}
	else
		elog(LOG, "Unable to send e-mail: curl_easy_init failed");

	/*
	 * Free other stuff we allocated. We run in a long-lived memory context
	 * so we have to be careful to not leak.
	 */
	pfree(rawstring);
	list_free(elemlist);
	pfree(from);
	pfree(upload_ctx.body.data);
}
#endif

int send_alert(const GpErrorData * errorData)
{

	char subject[128];
	bool send_via_email = true;
	char email_priority[2];

	static char previous_subject[128];
	pg_time_t current_time;
	static pg_time_t previous_time;
	static GpErrorDataFixFields previous_fix_fields;

	elog(DEBUG2,"send_alert: %s: %s",errorData->error_severity, errorData->error_message);

	/*
	 * SIGPIPE must be ignored, or we will have problems.
	 *
	 * but this is already set in syslogger.c, so we are OK
	 * //pqsignal(SIGPIPE, SIG_IGN);  // already set in syslogger.c
	 *
	 */

	/* Set up a subject line for the alert.  set_alert_severity will limit it to 127 bytes just to be safe. */
	/* Assign a severity and email priority for this alert*/

	set_alert_severity(errorData,
						subject,
						&send_via_email,
						email_priority);


	/*
	 * Check to see if we are sending the same message as last time.
	 * This could mean the system is in a loop generating an error over and over,
	 * or the application is just re-doing the same bad request over and over.
	 *
	 * This is pretty crude, as we don't consider loops where we alternate between a small
	 * number of messages.
	 */

	if (strcmp(subject,previous_subject)==0)
	{
		/*
		 * Looks like the same message based on the errMsg, but we need to
		 * investigate further.
		 */
		bool same_message_repeated = true;

		/*
		 * If the message is from a different segDB, consider it a different message.
		 */
		if (errorData->fix_fields.gp_segment_id != previous_fix_fields.gp_segment_id)
			same_message_repeated = false;
		if (errorData->fix_fields.gp_is_primary != previous_fix_fields.gp_is_primary)
			same_message_repeated = false;
		/*
		 * If the message is from a different user, consider it a different message,
		 * unless it is a FATAL, because an application repeatedly sending in a request
		 * that crashes (SIGSEGV) will get a new session ID each time
		 */
		if (errorData->fix_fields.gp_session_id != previous_fix_fields.gp_session_id)
			if (strcmp(errorData->error_severity,"FATAL") != 0)
				same_message_repeated = false;
		/*
		 * Don't consider gp_command_count, because a loop where the application is repeatedly
		 * sending a bad request will have a changing command_count.
		 *
		 * Likewise, the transaction ids will be changing each time, so don't consider them.
		 */

		if (same_message_repeated)
		{
			current_time = (pg_time_t)time(NULL);
			/*
			 * This is the same alert as last time.  Limit us to one repeat alert every 30 seconds
			 * to avoid spamming the sysAdmin's mailbox.
			 *
			 * We don't just turn off the alerting until a different message comes in, because
			 * if enough time has passed, this message might (probably?) refer to a new issue.
			 *
			 * Note that the message will still exist in the log, it's just that we won't
			 * send it via e-mail.
			 */

			if (current_time - previous_time < 30)
			{
				/* Bail out here rather than send the alert. */
				elog(DEBUG2,"Suppressing repeats of this alert messages...");
				return -1;
			}
		}

	}

	strcpy(previous_subject, subject);
	previous_time = (pg_time_t)time(NULL);
	memcpy(&previous_fix_fields,&errorData->fix_fields,sizeof(GpErrorDataFixFields));

#if defined(HAVE_DECL_CURLOPT_MAIL_FROM) && HAVE_DECL_CURLOPT_MAIL_FROM
	if (send_via_email)
		send_alert_via_email(errorData, subject, email_priority);
	else
		elog(DEBUG4,"Not sending via e-mail");
#endif

	return 0;
}


static size_t
pg_strnlen(const char *str, size_t maxlen)
{
	const char *p = str;

	while (maxlen-- > 0 && *p)
		p++;
	return p - str;
}

static void move_to_next_chunk(CSVChunkStr * chunkstr,
		const PipeProtoChunk * saved_chunks)
{
	Assert(chunkstr != NULL);
	Assert(saved_chunks != NULL);

	if (chunkstr->chunk != NULL)
		if (chunkstr->p - chunkstr->chunk->data >= chunkstr->chunk->hdr.len)
		{
			/* switch to next chunk */
			if (chunkstr->chunk->hdr.next >= 0)
			{
				chunkstr->chunk = &saved_chunks[chunkstr->chunk->hdr.next];
				chunkstr->p = chunkstr->chunk->data;
			}
			else
			{
				/* no more chunks */
				chunkstr->chunk = NULL;
				chunkstr->p = NULL;
			}
		}
}

char *
get_str_from_chunk(CSVChunkStr *chunkstr, const PipeProtoChunk *saved_chunks)
{
	int wlen = 0;
	int len = 0;
	char * out = NULL;

	Assert(chunkstr != NULL);
	Assert(saved_chunks != NULL);

	move_to_next_chunk(chunkstr, saved_chunks);

	if (chunkstr->p == NULL)
	{
		return strdup("");
	}

	len = chunkstr->chunk->hdr.len - (chunkstr->p - chunkstr->chunk->data);

	/* Check if the string is an empty string */
	if (len > 0 && chunkstr->p[0] == '\0')
	{
		chunkstr->p++;
		move_to_next_chunk(chunkstr, saved_chunks);

		return strdup("");
	}

	if (len == 0 && chunkstr->chunk->hdr.next >= 0)
	{
		const PipeProtoChunk *next_chunk =
				&saved_chunks[chunkstr->chunk->hdr.next];
		if (next_chunk->hdr.len > 0 && next_chunk->data[0] == '\0')
		{
			chunkstr->p++;
			move_to_next_chunk(chunkstr, saved_chunks);
			return strdup("");
		}
	}

	wlen = pg_strnlen(chunkstr->p, len);

	if (wlen < len)
	{
		// String all contained in this chunk
		out = malloc(wlen + 1);
		memcpy(out, chunkstr->p, wlen + 1); // include the null byte
		chunkstr->p += wlen + 1; // skip to start of next string.
		return out;
	}

	out = malloc(wlen + 1);
	memcpy(out, chunkstr->p, wlen);
	out[wlen] = '\0';
	chunkstr->p += wlen;

	while (chunkstr->p)
	{
		move_to_next_chunk(chunkstr, saved_chunks);
		if (chunkstr->p == NULL)
			break;
		len = chunkstr->chunk->hdr.len - (chunkstr->p - chunkstr->chunk->data);

		wlen = pg_strnlen(chunkstr->p, len);

		/* Write OK, don't forget to account for the trailing 0 */
		if (wlen < len)
		{
			// Remainder of String all contained in this chunk
			out = realloc(out, strlen(out) + wlen + 1);
			strncat(out, chunkstr->p, wlen + 1); // include the null byte

			chunkstr->p += wlen + 1; // skip to start of next string.
			return out;
		}
		else
		{
			int newlen = strlen(out) + wlen;
			out = realloc(out, newlen + 1);
			strncat(out, chunkstr->p, wlen);
			out[newlen] = '\0';

			chunkstr->p += wlen;
		}
	}

	return out;
}

#if defined(HAVE_DECL_CURLOPT_MAIL_FROM) && HAVE_DECL_CURLOPT_MAIL_FROM
/*
 * Support functions for building an alert email.
 */

/*
 *  The message is read a line at a time and the newlines converted
 *  to \r\n.  Unfortunately, RFC 822 states that bare \n and \r are
 *  acceptable in messages and that individually they do not constitute a
 *  line termination.  This requirement cannot be reconciled with storing
 *  messages with Unix line terminations.  RFC 2822 rescues this situation
 *  slightly by prohibiting lone \r and \n in messages.
 */
static void
add_to_message(StringInfo buf, const char *newstr_in)
{
	const char * newstr = newstr_in;
	char * p;
	if (newstr == NULL)
		return;

	/* Drop any leading \n characters:  Not sure what to do with them */
	while (*newstr == '\n')
		newstr++;

	/* Scan for \n, and convert to \r\n */
	while ((p = strchr(newstr,'\n')) != NULL)
	{
		/* Don't exceed 900 chars added to this line, so total line < 1000 */
		if (p - newstr >= 900)
		{
			appendBinaryStringInfo(buf, newstr, 898);
			appendStringInfoString(buf, "\r\n\t");
			newstr += 898;
		}
		else if (p - newstr >=2 && *(p-1) != '\r')
		{
			appendBinaryStringInfo(buf, newstr, p - newstr);
			appendStringInfoString(buf, "\r\n\t");
			newstr = p+1;
		}
		else
		{
			appendBinaryStringInfo(buf, newstr, p - newstr + 1);
			newstr = p+1;
		}
	}
	appendStringInfoString(buf, newstr);
}

static size_t
messagebody_cb(void *ptr, size_t size, size_t nmemb, void *userp)
{
	upload_ctx *ctx = (upload_ctx *) userp;
	size_t len;

	len = size * nmemb;
	if ((size == 0) || (nmemb == 0) || (len < 1))
		return 0;

	if (len > ctx->body.len - ctx->consumed)
		len = ctx->body.len - ctx->consumed;

	memcpy(ptr, ctx->body.data + ctx->consumed, len);
	ctx->consumed += len;

    return len;
}

static void
build_messagebody(StringInfo buf, const GpErrorData *errorData, const char *subject,
		const char *email_priority)
{
	/* Perhaps better to use text/html ? */

	appendStringInfo(buf, "From: %s\r\n", gp_email_from);
	appendStringInfo(buf, "To: %s\r\n", gp_email_to);
	appendStringInfo(buf, "Subject: %s\r\n", subject);
	if (email_priority[0] != '\0' && email_priority[0] != '3') // priority not the default?
		appendStringInfo(buf, "X-Priority: %s", email_priority); // set a priority.  1 == highest priority, 5 lowest

	appendStringInfoString(buf,	"MIME-Version: 1.0\r\n"
			"Content-Type: text/plain;\r\n"
			"  charset=utf-8\r\n"
			"Content-Transfer-Encoding: 8bit\r\n\r\n");

	/* Lines must be < 1000 bytes long for 7bit or 8bit transfer-encoding */
	/* Perhaps use base64 encoding instead?  Or just wrap them? */

	/*
	 * How to identify which system is sending the alert?  Perhaps our
	 * hostname and port is good enough?
	 */
	appendStringInfoString(buf, "Alert from GPDB system");
	{
		char myhostname[255];	/* gethostname usually is limited to 65 chars out, but make this big to be safe */
		myhostname[0] = '\0';

		if (gethostname(myhostname, sizeof(myhostname)) == 0)
			appendStringInfo(buf, " %s on port %d", myhostname, PostPortNumber);
	}
	appendStringInfoString(buf,":\r\n\r\n");
	if (errorData->username != NULL &&  errorData->databasename != NULL &&
		strlen(errorData->username)>0 && strlen(errorData->databasename)>0)
	{
		appendStringInfoString(buf, errorData->username);
		if (errorData->remote_host != NULL && strlen(errorData->remote_host) > 0)
		{
			if (strcmp(errorData->remote_host,"[local]")==0)
				appendStringInfoString(buf, " logged on locally from master node");
			else
				appendStringInfo(buf, " logged on from host %s", errorData->remote_host);
		}
		appendStringInfo(buf, " connected to database %s\r\n",
					errorData->databasename);
	}
	if (errorData->fix_fields.omit_location != 't')
	{
		if (errorData->fix_fields.gp_segment_id != -1)
		{
			appendStringInfo(buf,"Error occurred on segment %d\r\n",
							 errorData->fix_fields.gp_segment_id);
		}
		else
			appendStringInfoString(buf, "Error occurred on master segment\r\n");
	}
	appendStringInfoString(buf, "\r\n");

	appendStringInfo(buf, "%s: ", errorData->error_severity);
	if (errorData->sql_state != NULL && pg_strnlen(errorData->sql_state,5)>4 &&
		strncmp(errorData->sql_state,"XX100",5)!=0 &&
		strncmp(errorData->sql_state,"00000",5)!=0)
	{
		appendStringInfo(buf, "(%s) ", errorData->sql_state);
	}
	appendStringInfoString(buf, errorData->error_message);
	appendStringInfoString(buf, "\r\n");
	appendStringInfoString(buf, "\r\n");

	if (errorData->error_detail != NULL &&strlen(errorData->error_detail) > 0)
	{
		appendStringInfoString(buf, _("DETAIL:  "));
		add_to_message(buf, errorData->error_detail);
		appendStringInfoString(buf, "\r\n");
	}
	if (errorData->error_hint != NULL &&strlen(errorData->error_hint) > 0)
	{
		appendStringInfoString(buf, _("HINT:  "));
		add_to_message(buf, errorData->error_hint);
		appendStringInfoString(buf, "\r\n");
	}
	if (errorData->internal_query != NULL &&strlen(errorData->internal_query) > 0)
	{
		appendStringInfoString(buf, _("QUERY:  "));
		add_to_message(buf, errorData->internal_query);
		appendStringInfoString(buf, "\r\n");
	}
	if (errorData->error_context != NULL && strlen(errorData->error_context) > 0)
	{
		appendStringInfoString(buf, _("CONTEXT:  "));
		add_to_message(buf, errorData->error_context);
		appendStringInfoString(buf, "\r\n");
	}
	if (errorData->fix_fields.omit_location != 't')
	{
		if (errorData->error_filename != NULL && strlen(errorData->error_filename) > 0)
		{
			appendStringInfoString(buf, _("LOCATION:  "));

			if (errorData->error_func_name && strlen(errorData->error_func_name) > 0)
				appendStringInfo(buf, "%s, ", errorData->error_func_name);

			appendStringInfo(buf, "%s:%d\r\n",
							 errorData->error_filename,
							 errorData->fix_fields.error_fileline);
		}
		if (errorData->stacktrace != NULL && strlen(errorData->stacktrace) > 0)
		{
			appendStringInfoString(buf, "STACK TRACE:\r\n\t");
			add_to_message(buf, errorData->stacktrace);
			appendStringInfoString(buf, "\r\n");
		}
	}
	if (errorData->debug_query_string != NULL &&strlen(errorData->debug_query_string) > 0)
	{
		appendStringInfoString(buf, _("STATEMENT:  "));
		add_to_message(buf, errorData->debug_query_string);
		appendStringInfoString(buf, "\r\n");
	}
}

/*
 * Pull out just the e-mail address from a possibly human-readable string
 * like:
 *
 * Full Name <email@example.com>
 */
static char *
extract_email_addr(char *str)
{
	char	   *begin;
	char	   *end;

	begin = strchr(str, '<');
	if (begin != NULL)
	{
		begin++;
		end = strchr(begin, '>');
		if (end != NULL)
		{
			int			len = end - begin;
			char	   *email;

			email = palloc(len + 1);
			memcpy(email, begin, len);
			email[len] = '\0';

			return email;
		}
	}
	return pstrdup(str);
}

static bool
SplitMailString(char *rawstring, char delimiter,
					  List **namelist)
{
	char	   *nextp = rawstring;
	bool		done = false;

	*namelist = NIL;

	while (isspace((unsigned char) *nextp))
		nextp++;				/* skip leading whitespace */

	if (*nextp == '\0')
		return true;			/* allow empty string */

	/* At the top of the loop, we are at start of a new address. */
	do
	{
		char	   *curname;
		char	   *endp;

		curname = nextp;
		while (*nextp && *nextp != delimiter)
			nextp++;
		endp = nextp;
		if (curname == nextp)
			return false;	/* empty unquoted name not allowed */



		while (isspace((unsigned char) *nextp))
			nextp++;			/* skip trailing whitespace */

		if (*nextp == delimiter)
		{
			nextp++;
			while (isspace((unsigned char) *nextp))
				nextp++;		/* skip leading whitespace for next */
			/* we expect another name, so done remains false */
		}
		else if (*nextp == '\0')
			done = true;
		else
			return false;		/* invalid syntax */

		/* Now safe to overwrite separator with a null */
		*endp = '\0';

		/*
		 * Finished isolating current name --- add it to list
		 */
		*namelist = lappend(*namelist, curname);

		/* Loop back if we didn't reach end of string */
	} while (!done);

	return true;
}
#endif /* HAVE_DECL_CURLOPT_MAIL_FROM */
