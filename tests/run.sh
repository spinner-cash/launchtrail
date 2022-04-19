#!/usr/bin/env bash

test "$#" -eq 0 && echo "USAGE: $0 [test ...]" && exit 1

dir="$(dirname $0)"
input=$(mktemp test-XXXXXXXX.repl)
echo "#!/usr/bin/env ic-repl" >"$input"
echo "let hello_sha256 = \"$(shasum -a 256 ../dist/hello.wasm|cut -d\  -f1)\";" >>"$input"
cat "$dir/prelude.repl" >>"$input"

while [ "$#" -ge 1 ]; do
    test="$1"
    file="$test"
    test -f "$file" || file="$1.repl"
    test -f "$file" || (echo "Test '$test' does not exist or is not readable." && exit 1)
    shift

    cat $file >>"$input"
    chmod 755 "$input"
done

./$input
code="$?"
test "$code" -eq 0 && rm -f "$input" && exit 0
test "$code" -ne 0 && echo "Kept input file '$input'" && exit "$code"
