package pms

import "testing"
import "fmt"


func TestextractEmail(t *testing.T) {
/*	
	name,host, err := extractEmail(string("asfasasfases"))

	if err != nil {
		t.Error("Error")
	}
	
	fmt.Println(err)
*/
	t.Error("TestF")
}

/*
func BenchmarkHello(b *testing.B) {
	for i := 0; i < b.N; i++ {
		fmt.Sprintf("hello")
	}
}
*/

func ExampleHello() {
	fmt.Println("hello")
	// Output: hello
}

func BenchmarkextractEmail(b *testing.B) {
	for i := 0; i < b.N; i++ {
		extractEmail(string("asfasasfases"))
	}
}
