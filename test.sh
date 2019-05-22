#! /usr/bin/env sh
echo "mode: count" > profile.cov
TP=$(go list -f '{{if len .GoFiles}}{{.ImportPath}}{{end}}' ./... | grep -v "/vendor/" | grep -v "zenodb/zeno" | grep -v "zenodb/zeno-cli")
CP=$(echo $TP | tr ' ', ',')
set -x
for pkg in $TP; do \
	GO111MODULE=on go test -covermode=atomic -test.coverpkg "$CP" -c -o thetest && sudo -E ./thetest -test.v -test.coverprofile=profile_tmp.cov $pkg && sudo chmod 666 profile_tmp.cov || exit 1; \
	tail -n +2 profile_tmp.cov >> profile.cov; \
done
exit $?
