TEMPLATE = lib
TARGET = gnunetsetup_qt
dlltarget = $(TARGET)
CONFIG += @QT_CONFIG@ dll
INCLUDEPATH = ../../include ../lib . @INCLUDEPATH@ ../../..
DLLDESTDIR = .
LIBS = -L../../../src/util -lgnunetutil -L../../../src/setup/lib -lgnunetsetup
QMAKE_LIBDIR += -L/opt/guile/lib -L/usr/lib -L/lib 
QMAKE_LFLAGS += -shared

target.path = /usr/local/lib
INSTALLS += target

SOURCES = qtconfig.cc \
					setupWizard.cc
HEADERS = setupWizard.h
FORMS = gnunet-setup.ui enhanced.ui
