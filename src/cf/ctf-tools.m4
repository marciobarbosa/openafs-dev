AC_DEFUN([OPENAFS_CTF_TOOLS_CHECKS],[

CTF_DEFAULT_PATH="$PATH:/usr/bin:/opt/onbld/bin/$HOST_CPU"

AC_ARG_WITH([ctf-tools],
        AS_HELP_STRING([--with-ctf-tools],
        [directory where the ctf tools can be found]),
        [CTF_TOOLS="$withval"],
        [CTF_TOOLS="check"])

AS_CASE([$CTF_TOOLS],
        [check], [AC_PATH_PROG([CTFCONVERT], [ctfconvert], [], [$CTF_DEFAULT_PATH])
                  AC_PATH_PROG([CTFMERGE], [ctfmerge], [], [$CTF_DEFAULT_PATH])],

        [yes],   [AC_PATH_PROG([CTFCONVERT], [ctfconvert], [], [$CTF_DEFAULT_PATH])
                  AC_PATH_PROG([CTFMERGE], [ctfmerge], [], [$CTF_DEFAULT_PATH])
                  AS_IF([test "x$CTFCONVERT" = "x" -o "x$CTFMERGE" = "x"],
                        [AC_ERROR("CTF tools not found")])],

        [no],    [],

        [AC_PATH_PROG([CTFCONVERT], [ctfconvert], [], [$CTF_TOOLS])
         AC_PATH_PROG([CTFMERGE], [ctfmerge], [], [$CTF_TOOLS])
         AS_IF([test "x$CTFCONVERT" = "x" -o "x$CTFMERGE" = "x"],
               [AC_ERROR("CTF tools not found")])]
)

AC_SUBST(CTFCONVERT)
AC_SUBST(CTFMERGE)
])
