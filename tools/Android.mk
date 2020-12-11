LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := testpayload
LOCAL_LDFLAGS   += -llog -g
LOCAL_CFLAGS    += -DDEBUG -g

LOCAL_SRC_FILES := testpayload.c

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_MODULE := ex
LOCAL_LDFLAGS   += -llog
LOCAL_CFLAGS    += -DDEBUG

LOCAL_SRC_FILES := execve.c

include $(BUILD_EXECUTABLE)
