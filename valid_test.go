package main

import (
	"fmt"
	"testing"
)

func TestGetMail(t *testing.T) {
	user,domain := getMail("test@test.com");

	if user != "test" {
		t.Errorf("User error: test != %s",user)
	}

	if domain != "test.com" {
		t.Errorf("Domain error: test.com != %s",domain)
	}
}

func TestValidHost(t *testing.T) {
	check := validHost("\\sf%&test.com")
	
	if check != "" {
		t.Errorf("validHost error")
	}

	check = validHost("test.com")
	
	if check != "test.com" {
		t.Errorf("validHost error")	
	}
}

func ExampleGetMail() {
	user,domain := getMail("test@test.com");
	
	fmt.Println(domain)
	fmt.Println(user)
	// Output:
	// test.com
	// test
}
