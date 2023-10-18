FROM golang:1.21 as build

WORKDIR /go/src/app
COPY . .

RUN go mod download
RUN CGO_ENABLED=0 go build -buildvcs=false -o /go/bin/app

# Here we use distroless image from https://github.com/GoogleContainerTools/distroless
# add :debug tag to build with busybox
FROM gcr.io/distroless/static-debian12
COPY --from=build /go/bin/app /
ENTRYPOINT ["/cleaner"]