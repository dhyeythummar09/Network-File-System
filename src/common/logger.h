#ifndef LOGGER_H
#define LOGGER_H

#include <stdarg.h>

// Public logging API (implementations reside in logger.c)
void log_info(const char* fmt, ...);
void log_warn(const char* fmt, ...);
void log_error(const char* fmt, ...);
void log_request(const char* ip, int port, const char* user, const char* fmt, ...);

// Backward-compatible macros (preserve existing call sites using LOG_*)
#define LOG_INFO(...)   log_info(__VA_ARGS__)
#define LOG_WARN(...)   log_warn(__VA_ARGS__)
#define LOG_ERROR(...)  log_error(__VA_ARGS__)
#define LOG_REQUEST(ip, port, user, fmt, ...)  log_request(ip, port, user, fmt, ##__VA_ARGS__)

#endif // LOGGER_H
