#!/bin/sh
# A fake yamn client for encoder_test.go.  The test copies it into a
# temp dir next to a file "mode"; it records its arguments, stdin, its
# environment and the files of --dir in record/, then acts on the mode.
here=$(dirname "$0")
rec="$here/record"
mkdir -p "$rec"
printf '%s\n' "$@" > "$rec/args"
env > "$rec/env"
cat > "$rec/stdin"
dir= chain=
while [ $# -gt 0 ]; do
	case "$1" in
	--dir) dir=$2; shift ;;
	-l) chain=$2; shift ;;
	esac
	shift
done
ls -A "$dir" > "$rec/ls"
cp "$dir/yamn.yml" "$dir/pubring.mix" "$rec/"
stat -c %a "$dir" > "$rec/mode"
echo "$dir" > "$rec/dir"
first=${chain%%,*}

mail() {
	printf 'From yamn Thu Oct 22 11:15:27 2026\n'
	printf 'To: %s\nFrom: pinger@example.org\nSubject: yamn-0.2.7\n\n' "$1"
	printf '::\nRemailer-Type: yamn-0.2.7\n\n-----BEGIN REMAILER MESSAGE-----\n20480\n'
	printf '>From the body, escaped\nAAAA\n-----END REMAILER MESSAGE-----\n\n'
}

case $(cat "$here/mode") in
ok) mail "$first" ;;
okwarn) mail "$first"; echo "a warning" >&2 ;;
two) mail "$first"; mail "$first" ;;
none) echo "no mbox here" ;;
wrongto) mail "other@example.org" ;;
exit1)
	echo "2026/10/22 11:15:27 [ERROR]   $first: Remailer address not found in public keyring" >&2
	exit 1 ;;
sleep) exec sleep 30 ;;
esac
exit 0
