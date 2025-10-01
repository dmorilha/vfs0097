CXX=clang++

CXXFLAGS+=-g
CXXFLAGS+=-O0
CXXFLAGS+=-std=c++20

CXXFLAGS+=$(shell pkg-config --cflags openssl;)
CXXFLAGS+=$(shell pkg-config --cflags libusb-1.0;)

LIBS+=$(shell pkg-config --libs openssl;)
LIBS+=$(shell pkg-config --libs libusb-1.0;)

#CXXFLAGS+=-fsanitize=thread

main: main.cc
	$(CXX) $(CXXFLAGS) $(LIBS) -o $@ $<;
