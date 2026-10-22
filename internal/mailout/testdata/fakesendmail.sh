#!/bin/sh
# A stand-in for sendmail in the tests: writes its arguments, one per
# line, to $FAKESENDMAIL_OUT.args and stdin to $FAKESENDMAIL_OUT.stdin.
out=${FAKESENDMAIL_OUT:?}
for a in "$@"; do printf '%s\n' "$a"; done > "$out.args"
cat > "$out.stdin"
if [ -n "$FAKESENDMAIL_STDERR" ]; then printf '%s\n' "$FAKESENDMAIL_STDERR" >&2; fi
if [ -n "$FAKESENDMAIL_SLEEP" ]; then exec sleep "$FAKESENDMAIL_SLEEP"; fi
exit "${FAKESENDMAIL_EXIT:-0}"
