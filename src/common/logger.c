// Implementation of logging functions moved from header-only macros.
// Provides timestamped, formatted logging with millisecond precision.

#include "logger.h"

#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <stdarg.h>

// Internal helper: build timestamp string (YYYY-MM-DD HH:MM:SS.mmm)
static void build_timestamp(char* buf, size_t sz) {
	struct timeval tv; gettimeofday(&tv, NULL);
	struct tm tm_info; localtime_r(&tv.tv_sec, &tm_info);
	snprintf(buf, sz, "%04d-%02d-%02d %02d:%02d:%02d.%03ld",
			 tm_info.tm_year + 1900, tm_info.tm_mon + 1, tm_info.tm_mday,
			 tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec, tv.tv_usec / 1000);
}

static void vlog_generic(FILE* stream, const char* level, const char* fmt, va_list ap) {
	char ts[64]; build_timestamp(ts, sizeof(ts));
	fprintf(stream, "[%s] [%s] ", ts, level);
	vfprintf(stream, fmt, ap);
	fputc('\n', stream);
	fflush(stream);
}

void log_info(const char* fmt, ...) {
	va_list ap; va_start(ap, fmt); vlog_generic(stdout, "INFO", fmt, ap); va_end(ap);
}

void log_warn(const char* fmt, ...) {
	va_list ap; va_start(ap, fmt); vlog_generic(stdout, "WARN", fmt, ap); va_end(ap);
}

void log_error(const char* fmt, ...) {
	va_list ap; va_start(ap, fmt); vlog_generic(stderr, "ERROR", fmt, ap); va_end(ap);
}

void log_request(const char* ip, int port, const char* user, const char* fmt, ...) {
	char ts[64]; build_timestamp(ts, sizeof(ts));
	if (!user) user = "-";
	fprintf(stdout, "[%s] [%s:%d] [%s] ", ts, ip ? ip : "0.0.0.0", port, user);
	va_list ap; va_start(ap, fmt); vfprintf(stdout, fmt, ap); va_end(ap);
	fputc('\n', stdout); fflush(stdout);
}
