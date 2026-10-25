package policy

import (
	"path"
	"strings"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/common/types/traits"
	"cel.dev/cel-go/ext"
)

// newEnv returns the CEL environment rule conditions are compiled in.
//
// Variables:
//
//	tool    string            the tool's name as the client sees it (fs__read_file)
//	server  string            the server the call goes to (fs)
//	args    map(string, dyn)  the call's arguments
//
// Besides CEL's standard library and its string extensions, conditions can
// use:
//
//	under(path, dir)   true if path is an absolute path inside dir, after
//	                   resolving "." and ".." (so "/workspace/../etc" is not
//	                   under "/workspace"). Symlinks can't be seen from here.
//	values(args, keys) the values of those keys that args has, with lists
//	                   flattened: values(args, ["path", "paths"]) covers a
//	                   tool taking one path and a tool taking several.
func newEnv() (*cel.Env, error) {
	return cel.NewEnv(
		cel.Variable("tool", cel.StringType),
		cel.Variable("server", cel.StringType),
		cel.Variable("args", cel.MapType(cel.StringType, cel.DynType)),
		cel.OptionalTypes(),
		ext.Strings(),
		cel.Function("under",
			cel.Overload("under_string_string", []*cel.Type{cel.StringType, cel.StringType}, cel.BoolType,
				cel.BinaryBinding(func(p, dir ref.Val) ref.Val {
					ps, ok1 := p.(types.String)
					ds, ok2 := dir.(types.String)
					if !ok1 || !ok2 {
						return types.MaybeNoSuchOverloadErr(p)
					}
					return types.Bool(under(string(ps), string(ds)))
				}))),
		cel.Function("values",
			cel.Overload("values_map_list", []*cel.Type{cel.MapType(cel.StringType, cel.DynType), cel.ListType(cel.StringType)},
				cel.ListType(cel.DynType),
				cel.BinaryBinding(func(m, keys ref.Val) ref.Val {
					mapper, ok1 := m.(traits.Mapper)
					lister, ok2 := keys.(traits.Lister)
					if !ok1 || !ok2 {
						return types.MaybeNoSuchOverloadErr(m)
					}
					return values(mapper, lister)
				}))),
	)
}

// under reports whether p is an absolute path inside dir. Relative paths
// aren't: what they point at depends on the server's working directory.
func under(p, dir string) bool {
	if !strings.HasPrefix(p, "/") || !strings.HasPrefix(dir, "/") || strings.ContainsRune(p, 0) {
		return false
	}
	p, dir = path.Clean(p), path.Clean(dir)
	return dir == "/" || p == dir || strings.HasPrefix(p, dir+"/")
}

func values(m traits.Mapper, keys traits.Lister) ref.Val {
	var out []ref.Val
	it := keys.Iterator()
	for it.HasNext() == types.True {
		v, found := m.Find(it.Next())
		if !found {
			continue
		}
		if list, ok := v.(traits.Lister); ok {
			items := list.Iterator()
			for items.HasNext() == types.True {
				out = append(out, items.Next())
			}
			continue
		}
		out = append(out, v)
	}
	return types.NewRefValList(types.DefaultTypeAdapter, out)
}
