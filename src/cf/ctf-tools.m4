AC_DEFUN([OPENAFS_CTF_TOOLS_CHECKS],[
CTFCONVERT=
CTFMERGE=

DEFAULT_PATH="$PATH:/usr/bin:/opt/onbld/bin/$HOST_CPU"

AS_CASE([$CTF_TOOLS],
        [check], [AC_PATH_PROG([CTFCONVERT], [ctfconvert], [no], [path = $DEFAULT_PATH])]
                 [AC_PATH_PROG([CTFMERGE], [ctfmerge], [no], [path=$DEFAULT_PATH])]
                 [AS_IF([test "x$CTFCONVERT" = "xno" -o "x$CTFMERGE" = "xno"],
                        [CTFCONVERT="" CTFMERGE=""])],

        [yes],   [AC_PATH_PROG([CTFCONVERT], [ctfconvert], [no], [path = $DEFAULT_PATH])]
                 [AC_PATH_PROG([CTFMERGE], [ctfmerge], [no], [path=$DEFAULT_PATH])]
                 [AS_IF([test "x$CTFCONVERT" = "xno" -o "x$CTFMERGE" = "xno"],
                        [AC_ERROR("CTF tools not found")])],

        [no],    [],

        [AC_PATH_PROG([CTFCONVERT], [ctfconvert], [no], [path = $CTF_TOOLS])
         AC_PATH_PROG([CTFMERGE], [ctfmerge], [no], [path = $CTF_TOOLS])
         AS_IF([test "x$CTFCONVERT" = "xno" -o "x$CTFMERGE" = "xno"],
               [AC_ERROR("CTF tools not found")])]
)

AS_IF([test "x$enable_debug_kernel" = "xno"], [CTFCONVERT="" CTFMERGE=""])

AC_SUBST(CTFCONVERT)
AC_SUBST(CTFMERGE)
])
