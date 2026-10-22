package replies

import (
	"encoding/base64"
	"net/mail"
	"strings"
	"testing"
)

func header(cte string) mail.Header {
	return mail.Header{"Content-Transfer-Encoding": {cte}}
}

func TestBody(t *testing.T) {
	tests := []struct {
		name string
		h    mail.Header
		in   string
		want string
	}{
		{"plain", nil, "a\nb\n", "a\nb\n"},
		{"7bit", header("7bit"), "a\n", "a\n"},
		{"8bit", header(" 8BIT "), "ä\n", "ä\n"},
		{"binary", header("binary"), "a\n", "a\n"},
		{"CRLF", nil, "a\r\nb\r\n\r\nc", "a\nb\n\nc"},
		{"lone CR", nil, "a\rb\r\n", "a\nb\n"},
		{"QP", header("Quoted-Printable"), "a=3Db=\r\nc\r\n=3D-=3D-\r\nlong=\nline\n", "a=bc\n=-=-\nlongline\n"},
		{"base64", header("base64"), "YT1i\r\nCmM=\r\n", "a=b\nc"},
		{"dash-escaped", nil, "- -----Begin Mix Key-----\n- - x\n-- y\n -z\n", "-----Begin Mix Key-----\n- x\n-- y\n -z\n"},
	}
	for _, tt := range tests {
		got, err := Body(tt.h, []byte(tt.in))
		if err != nil {
			t.Errorf("%s: %v", tt.name, err)
			continue
		}
		if string(got) != tt.want {
			t.Errorf("%s: got %q, want %q", tt.name, got, tt.want)
		}
	}

	for name, h := range map[string]mail.Header{
		"unknown encoding": header("x-uuencode"),
		"bad base64":       header("base64"),
	} {
		if got, err := Body(h, []byte("a=zz!\n")); err == nil {
			t.Errorf("%s: got %q", name, got)
		}
	}
}

// signedKeyReply is t_65.key as a PGP clear-signed CRLF message.
func signedKeyReply(t *testing.T) string {
	var b strings.Builder
	b.WriteString("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n")
	for _, l := range strings.Split(string(readFile(t, "replies/t_65.key")), "\n") {
		if strings.HasPrefix(l, "-") {
			l = "- " + l
		}
		b.WriteString(l + "\n")
	}
	b.WriteString("-----BEGIN PGP SIGNATURE-----\n\niQEzBAEBCAAdFiEE\n=abcd\n-----END PGP SIGNATURE-----\n")
	return strings.ReplaceAll(b.String(), "\n", "\r\n")
}

func TestBodyKeyReplies(t *testing.T) {
	signed := signedKeyReply(t)
	if !strings.Contains(signed, "- -----Begin Mix Key-----\r\n") {
		t.Fatal("not dash-escaped")
	}
	if r := ParseKey([]byte(signed)); len(r.Keys) != 0 {
		t.Fatal("dash-escaped reply parsed without Body")
	}

	plain := string(readFile(t, "replies/t_65.key"))
	var b64 strings.Builder
	enc := base64.StdEncoding.EncodeToString([]byte(strings.ReplaceAll(plain, "\n", "\r\n")))
	for len(enc) > 76 {
		b64.WriteString(enc[:76] + "\r\n")
		enc = enc[76:]
	}
	b64.WriteString(enc + "\r\n")
	// QP with soft line breaks inside the summary line and the pk.
	qp := strings.ReplaceAll(plain, "=", "=3D")
	qp = strings.Replace(qp, "yamn@virebent.art dd34", "yamn@virebent.art=\r\n dd34", 1)
	qp = strings.Replace(qp, "ff64d55659f8cd2f", "ff64d556=\n59f8cd2f", 1)

	for name, in := range map[string]struct {
		h    mail.Header
		body string
	}{
		"signed": {nil, signed},
		"base64": {header("base64"), b64.String()},
		"QP":     {header("quoted-printable"), qp},
	} {
		body, err := Body(in.h, []byte(in.body))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		r := ParseKey(body)
		if len(r.Errors) != 0 || len(r.Keys) != 1 || r.Keys[0].String() != victorHeader {
			t.Errorf("%s: got %d keys, errors %q", name, len(r.Keys), errorStrings(r.Errors))
		}
	}
}
