// full path: github.com/google/go-flow-levee/guides/quickstart
package quickstart

//import "log"
import "testing"
func Test_authenticate(t *testing.T)  {
	type VarTracer struct {
		tag string `datapolicy:"password"`
	}
	
	auth := &Authentication{"", ""}
	tracer := &VarTracer{""}
	//auth1 := &Authentication{"", ""}
	password := auth.Password
	pwd := tracer.tag
	//deepSink(*auth)	
	stringPrinterWrapperWarpper(pwd, false)/*  */
	//stringPrinter("hello world")/*  */
	if false{
		pwd = password
	}
	//log.Printf("unable to make authenticated request: incorrect authentication? %v", pwd)
	//log.Printf("unable to make authenticated request: incorrect authentication? %v%v%v", "2", "1", pwd)
	
	//log.Printf("unable to make authenticated request: incorrect authentication? %v", auth.Password)
}