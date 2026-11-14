// Copyright 2026 Dominik Schlosser
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pkg_test

import (
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

const module = "github.com/eudi-dev/eudi-dev/v3/"

// ADR-0034: the exported API of a public package uses only types from the
// standard library and pkg/. A caller outside the module cannot use an internal
// type. A type from a dependency ties the API to its versions. A map[any]any
// (raw CBOR decoder output) is refused as well.
func TestExportedAPIUsesOnlyPublicTypes(t *testing.T) {
	fset := token.NewFileSet()
	// The source importer resolves the unexported parts that use internal
	// packages and dependencies.
	config := types.Config{Importer: importer.ForCompiler(fset, "source", nil)}

	checked := 0
	err := filepath.WalkDir(".", func(dir string, entry fs.DirEntry, err error) error {
		if err != nil || !entry.IsDir() || dir == "." {
			return err
		}
		files := parseDir(t, fset, dir)
		if len(files) == 0 {
			return nil
		}
		pkg, err := config.Check(module+"pkg/"+filepath.ToSlash(dir), fset, files, nil)
		if err != nil {
			t.Fatalf("type-checking %s: %v", dir, err)
		}
		checked++
		for _, problem := range apiProblems(pkg) {
			t.Error(problem)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked == 0 {
		t.Fatal("no package found under pkg/")
	}
}

func parseDir(t *testing.T, fset *token.FileSet, dir string) []*ast.File {
	t.Helper()
	names, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	var files []*ast.File
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, file)
	}
	return files
}

// apiProblems lists the types in the exported API of pkg that an outside
// caller should not see.
func apiProblems(pkg *types.Package) []string {
	c := &apiCheck{seen: map[types.Type]bool{}}
	scope := pkg.Scope()
	for _, name := range scope.Names() {
		object := scope.Lookup(name)
		if !object.Exported() {
			continue
		}
		c.where = pkg.Name() + "." + name
		c.visit(object.Type())
		typeName, ok := object.(*types.TypeName)
		if !ok {
			continue
		}
		c.visit(typeName.Type().Underlying())
		if named, ok := types.Unalias(typeName.Type()).(*types.Named); ok {
			for method := range named.Methods() {
				if method.Exported() {
					c.where = pkg.Name() + "." + name + "." + method.Name()
					c.visit(method.Type())
				}
			}
		}
	}
	return c.problems
}

type apiCheck struct {
	where    string
	seen     map[types.Type]bool
	problems []string
}

func (c *apiCheck) visit(t types.Type) {
	if t == nil {
		return
	}
	switch t := t.(type) {
	case *types.Alias:
		c.visit(types.Unalias(t))
	case *types.Named:
		// A named type of pkg/ is checked where it is declared.
		if owner := t.Obj().Pkg(); owner != nil && !public(owner.Path()) {
			c.report("%s of %s", t.Obj().Name(), owner.Path())
		}
		for arg := range t.TypeArgs().Types() {
			c.visit(arg)
		}
	case *types.Pointer:
		c.visit(t.Elem())
	case *types.Slice:
		c.visit(t.Elem())
	case *types.Array:
		c.visit(t.Elem())
	case *types.Chan:
		c.visit(t.Elem())
	case *types.Map:
		if isAny(t.Key()) && isAny(t.Elem()) {
			c.report("map[any]any")
		}
		c.visit(t.Key())
		c.visit(t.Elem())
	case *types.Signature:
		c.visit(t.Params())
		c.visit(t.Results())
	case *types.Tuple:
		for v := range t.Variables() {
			c.visit(v.Type())
		}
	case *types.Struct:
		if c.seen[t] {
			return
		}
		c.seen[t] = true
		for field := range t.Fields() {
			if field.Exported() {
				c.visit(field.Type())
			}
		}
	case *types.Interface:
		if c.seen[t] {
			return
		}
		c.seen[t] = true
		for method := range t.Methods() {
			if method.Exported() {
				c.visit(method.Type())
			}
		}
	}
}

func (c *apiCheck) report(format string, args ...any) {
	c.problems = append(c.problems, fmt.Sprintf("%s exposes %s", c.where, fmt.Sprintf(format, args...)))
}

func isAny(t types.Type) bool {
	i, ok := t.Underlying().(*types.Interface)
	return ok && i.Empty()
}

func public(path string) bool {
	if rest, ok := strings.CutPrefix(path, module); ok {
		return strings.HasPrefix(rest, "pkg/")
	}
	return !strings.Contains(strings.SplitN(path, "/", 2)[0], ".")
}
