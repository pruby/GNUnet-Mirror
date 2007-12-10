BUILD_TARGET=linux
contains(BUILD_TARGET, mingw) {
	# Since this library cannot be loaded on Win32 (invalid memory access when 
	# <QApplication> is included), we build an executable

	TEMPLATE = app
	TARGET = gnunetsetup_qt
	CONFIG += @QT_CONFIG@
	target.path = /home/grothoff//bin
} else {
	TEMPLATE = lib
	TARGET = gnunetsetup_qt
	dlltarget = $(TARGET)
	CONFIG += @QT_CONFIG@ dll
	DLLDESTDIR = .
	QMAKE_LFLAGS += -shared
	target.path = /home/grothoff//lib
}
QMAKE_CXXFLAGS = -I/usr/include -I/usr/include/qt4 -I/home/grothoff//include 
INCLUDEPATH = ../../include ../lib . -I/usr/include -I/usr/include/qt4 -I/home/grothoff//include  ../../..
LIBS = -L../../../src/util -lgnunetutil -L../../../src/setup/lib -lgnunetsetup 
QMAKE_LIBDIR += /home/grothoff//lib 

INSTALLS += target

SOURCES = qtconfig.cc \
					setupWizard.cc
HEADERS = setupWizard.h
FORMS = gnunet-setup.ui enhanced.ui
