GIT_COMMIT := $(shell git rev-parse HEAD)
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD)
GIT_REPO := $(shell git ls-remote --get-url)
EXECUTABLE := "quorum-security-plugin-enterprise"
PACKAGE ?= quorum-security-plugin-enterprise
OUTPUT_DIR := "$(shell pwd)/build"
VERSION := "0.0.0"
LD_FLAGS="-X main.GitCommit=${GIT_COMMIT} -X main.GitBranch=${GIT_BRANCH} -X main.GitRepo=${GIT_REPO} \
-X main.Executable=${EXECUTABLE} -X main.Version=${VERSION} -X main.OutputDir=${OUTPUT_DIR}"
XC_ARCH := amd64
XC_OS := linux darwin
TARGET_DIRS := $(addsuffix -$(XC_ARCH), $(XC_OS))

.PHONY: ${OUTPUT_DIR}

default: clean test build zip
	@echo Done!
	@ls ${OUTPUT_DIR}/*

checkfmt: tools
	@GO_FMT_FILES="$$(goimports -l `find . -name '*.go' | grep -v vendor | grep -v proto`)"; \
	test -z "$${GO_FMT_FILES}" || ( echo "Please run 'make fixfmt' to format the following files: \n$${GO_FMT_FILES}"; exit 1 )

fixfmt: tools
	@goimports -w `find . -name '*.go' | grep -v vendor | grep -v proto`

test: tools
	@CGO_ENABLED=0 go test ./...

dist-local: clean build zip
	@[ "${PLUGIN_DEST_PATH}" ] || ( echo "Please provide PLUGIN_DEST_PATH env variable" ; exit 1)
	@mkdir -p ${PLUGIN_DEST_PATH}
	@cp ${OUTPUT_DIR}/$(shell go env GOOS)-$(shell go env GOARCH)/${PACKAGE}-${VERSION}.zip ${PLUGIN_DEST_PATH}/${PACKAGE}-${VERSION}.zip

dist: clean build zip
	@echo Done!
	@cat ${OUTPUT_DIR}/plugin-meta.json
	@ls ${OUTPUT_DIR}/*

build: checkfmt
	@mkdir -p ${OUTPUT_DIR}
	@echo Output to ${OUTPUT_DIR}
	@CGO_ENABLED=0 go run -ldflags=${LD_FLAGS} ./internal/metadata/gen.go
	@CGO_ENABLED=0 gox \
		-parallel=2 \
		-os="${XC_OS}" \
		-arch="${XC_ARCH}" \
		-ldflags="-s -w" \
		-output "${OUTPUT_DIR}/{{.OS}}-{{.Arch}}/${EXECUTABLE}" \
		.

zip: build $(TARGET_DIRS)

$(TARGET_DIRS):
	@zip -j -FS -q ${OUTPUT_DIR}/${PACKAGE}-${VERSION}-$@.zip ${OUTPUT_DIR}/*.json ${OUTPUT_DIR}/$@/*
	@shasum -a 256 ${OUTPUT_DIR}/${PACKAGE}-${VERSION}-$@.zip | awk '{print $$1}' > ${OUTPUT_DIR}/${PACKAGE}-${VERSION}-$@-sha256.checksum

tools: goimports gox

goimports:
ifeq (, $(shell which goimports))
	@GO111MODULE=off go get -u golang.org/x/tools/cmd/goimports
endif

gox:
ifeq (, $(shell which gox))
	@GO111MODULE=off go get -u github.com/mitchellh/gox
endif


clean:
	@rm -rf ${OUTPUT_DIR}