#!/bin/sh -ex

wget -q -O artifact_go.sh 'https://raw.githubusercontent.com/mdblp/tools/feature/add-golang-soup/artifact/artifact_go.sh'
chmod +x artifact_go.sh

. ./version.sh
./artifact_go.sh go
