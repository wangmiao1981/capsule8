IMAGE_TAG=getcapsule8/meltdown-detector

.PHONY: all container push run clean

all: container

meltdown: main.go
	CGO_ENABLED=0 go build .

container: meltdown
	docker build -t $(IMAGE_TAG) .

push:
	docker push $(IMAGE_TAG)

run:
	docker run --cap-add SYS_ADMIN -v /sys/kernel/debug:/sys/kernel/debug:ro $(IMAGE_TAG)

clean:
	rm meltdown
