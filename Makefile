
TARGET 	= pingpong_buffer
SRC	= pingpong_buffer.c

CFLAGS += -std=gnu99 -Wall -O2 -pthread
LDFLAGS += -pthread


$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $^ -o $@
clean:
	rm $(TARGET) -f
