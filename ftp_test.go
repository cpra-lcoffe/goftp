package goftp

import (
	"crypto/tls"
	"fmt"
	"os"
	"testing"
)

//import "fmt"

var goodServer string
var uglyServer string
var badServer string

func init() {
	//ProFTPD 1.3.5 Server (Debian)
	goodServer = "bo.mirror.garr.it:21"

	//Symantec EMEA FTP Server
	badServer = "ftp.packardbell.com:21"

	//Unknown server
	uglyServer = "ftp.musicbrainz.org:21"
}

func standard(host string) (msg string) {
	var err error
	var connection *FTP

	if connection, err = Connect(host); err != nil {
		return "Can't connect ->" + err.Error()
	}
	if err = connection.Login("anonymous", "anonymous"); err != nil {
		return "Can't login ->" + err.Error()
	}
	if _, err = connection.List(""); err != nil {
		return "Can't list ->" + err.Error()
	}
	connection.Close()
	return ""
}

func TestLogin_good(t *testing.T) {
	str := standard(goodServer)
	if len(str) > 0 {
		t.Error(str)
	}
}

func TestLogin_bad(t *testing.T) {
	str := standard(badServer)
	if len(str) > 0 {
		t.Error(str)
	}
}

func TestLogin_ugly(t *testing.T) {
	str := standard(uglyServer)
	if len(str) > 0 {
		t.Error(str)
	}
}

func TestLoginAuthTLS(t *testing.T) {
	host := os.Getenv("TEST_FTPES_HOST")
	port := os.Getenv("TEST_FTPES_PORT")
	username := os.Getenv("TEST_FTPES_USERNAME")
	password := os.Getenv("TEST_FTPES_PASSWORD")

	connection, err := ConnectDbg(fmt.Sprintf("%s:%s", host, port))
	if err != nil {
		t.Fatal(err)
	}

	config := &tls.Config{
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
		ClientSessionCache: tls.NewLRUClientSessionCache(32),
		ClientAuth:         tls.RequestClientCert,
	}

	if err = connection.LoginAuthTLS(config, username, password); err != nil {
		t.Fatal(err)
	}

	if _, err = connection.List("/"); err != nil {
		t.Fatal(err)
	}

	connection.Close()
	return
}
