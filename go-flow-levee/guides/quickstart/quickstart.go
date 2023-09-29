// full path: github.com/google/go-flow-levee/guides/quickstart
package quickstart

import "log"
//import "strconv"

type Authentication struct {
	Username string 
	Password string 
}
func stringPrinter(s string){
	log.Printf("unable to make authenticated request: incorrect authentication? %v", s)
}
func stringPrinterWarpper(b bool, si string){
	if si == "deeper_condition"{
		stringPrinter(si)
	}
}

func stringPrinterWrapperWarpper(s string, b bool){
	arg := s
	if s == "shallower_condition"{
		arg += " "
		//stringPrinterWarpper(true, s)//TODO: direct parameter not using raises error
		stringPrinterWarpper(true, arg)
		//strconv.Atoi(arg)//TODO: can not recoginize outside
	}
}

func authenticate(auth Authentication) (*AuthenticationResponse, error) {
	response, err := makeAuthenticationRequest(auth)
	if err != nil {
		log.Printf("unable to make authenticated request: incorrect authentication? %v", auth)
		return nil, err
	}
	return response, nil
}

// just a stub, to allow the code to compile
type AuthenticationResponse struct{}

// just a stub, to allow the code to compile
func makeAuthenticationRequest(Authentication) (*AuthenticationResponse, error) { return nil, nil }

//lint:file-ignore U1000 ignore unused functions
