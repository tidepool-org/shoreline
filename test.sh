#!/bin/sh
# set -x
go install github.com/jstemmer/go-junit-report@latest
go install github.com/t-yuki/gocover-cobertura@latest
go test -v -race -coverprofile=coverage.out ./... 2>&1 > testresults.txt
testPass=$?

echo "Results:"
cat testresults.txt

cat testresults.txt | go-junit-report  > test-report.xml
if [ $testPass -eq 1 ]; then
  echo "Test failled"
  exit 1
fi
echo "Success!"
gocover-cobertura < coverage.out > coverage.xml
go tool cover -html='coverage.out' -o coverReport.html
