
package main

import (
	"encoding/gob"
	"flag"
	"fmt"
	"os"
	"path"
	"reflect"

	"github.com/golang/mock/mockgen/model"

	pkg_ "github.com/trustbloc/vcs/pkg/restapi/v1/oidc4ci"
)

var output = flag.String("output", "", "The output file name, or empty to use stdout.")

func main() {
	flag.Parse()

	its := []struct{
		sym string
		typ reflect.Type
	}{
		
		{ "StateStore", reflect.TypeOf((*pkg_.StateStore)(nil)).Elem()},
		
		{ "OAuth2Provider", reflect.TypeOf((*pkg_.OAuth2Provider)(nil)).Elem()},
		
		{ "IssuerInteractionClient", reflect.TypeOf((*pkg_.IssuerInteractionClient)(nil)).Elem()},
		
		{ "HTTPClient", reflect.TypeOf((*pkg_.HTTPClient)(nil)).Elem()},
		
		{ "ClientManager", reflect.TypeOf((*pkg_.ClientManager)(nil)).Elem()},
		
		{ "ProfileService", reflect.TypeOf((*pkg_.ProfileService)(nil)).Elem()},
		
		{ "AckService", reflect.TypeOf((*pkg_.AckService)(nil)).Elem()},
		
		{ "CwtProofChecker", reflect.TypeOf((*pkg_.CwtProofChecker)(nil)).Elem()},
		
		{ "LDPProofParser", reflect.TypeOf((*pkg_.LDPProofParser)(nil)).Elem()},
		
	}
	pkg := &model.Package{
		// NOTE: This behaves contrary to documented behaviour if the
		// package name is not the final component of the import path.
		// The reflect package doesn't expose the package name, though.
		Name: path.Base("github.com/trustbloc/vcs/pkg/restapi/v1/oidc4ci"),
	}

	for _, it := range its {
		intf, err := model.InterfaceFromInterfaceType(it.typ)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Reflection: %v\n", err)
			os.Exit(1)
		}
		intf.Name = it.sym
		pkg.Interfaces = append(pkg.Interfaces, intf)
	}

	outfile := os.Stdout
	if len(*output) != 0 {
		var err error
		outfile, err = os.Create(*output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to open output file %q", *output)
		}
		defer func() {
			if err := outfile.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "failed to close output file %q", *output)
				os.Exit(1)
			}
		}()
	}

	if err := gob.NewEncoder(outfile).Encode(pkg); err != nil {
		fmt.Fprintf(os.Stderr, "gob encode: %v\n", err)
		os.Exit(1)
	}
}
