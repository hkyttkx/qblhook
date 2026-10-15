ARCHS = arm64 arm64e
TARGET = iphone:clang:16.5:14.0

include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = QBLHook
QBLHook_FILES = QBLHook.m
QBLHook_FRAMEWORKS = Foundation UIKit

include $(THEOS)/makefiles/library.mk
