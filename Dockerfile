FROM golang:buster

WORKDIR /app

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY *.go ./

RUN go build -o /dsm-certtool

EXPOSE 8080

CMD [ "/dsm-certtool" ]