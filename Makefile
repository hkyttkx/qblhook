ARCHS = arm64 arm64e
TARGET = iphone:clang:latest:14.0

include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = QBLHook
QBLHook_FILES = QBLHook.x
QBLHook_FRAMEWORKS = Foundation UIKit

include $(THEOS)/makefiles/library.mk
