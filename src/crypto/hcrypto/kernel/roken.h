#ifndef ROKEN_LIB_FUNCTION
#ifdef _WIN32
#  define ROKEN_LIB_CALL     __cdecl
#  ifdef ROKEN_LIB_DYNAMIC
#    define ROKEN_LIB_FUNCTION __declspec(dllimport)
#    define ROKEN_LIB_VARIABLE __declspec(dllimport)
#  else
#    define ROKEN_LIB_FUNCTION
#    define ROKEN_LIB_VARIABLE
#  endif
#else
#define ROKEN_LIB_FUNCTION
#define ROKEN_LIB_CALL
#define ROKEN_LIB_VARIABLE
#endif
#endif
