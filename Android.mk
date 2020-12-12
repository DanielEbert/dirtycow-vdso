LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := dcowvdso
LOCAL_LDFLAGS   += -llog -Wall
LOCAL_CFLAGS    += -DDEBUG -Wall

LOCAL_SRC_FILES := payload.h 0xdeadbeef.c

include $(BUILD_EXECUTABLE)
