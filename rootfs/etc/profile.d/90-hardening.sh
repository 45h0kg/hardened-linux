# New files private to their owner by default.
umask 077
# Idle interactive shells exit after 15 minutes; readonly so a user can't
# simply unset it.
if [ -z "${TMOUT:-}" ]; then TMOUT=900; readonly TMOUT; export TMOUT; fi
