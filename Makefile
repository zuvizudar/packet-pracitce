OBJS = test.o
SRCS = $(OBJS:%.0=%.c)
CFLAGS = -g -Wall
LDLIBS = 
TARGET = test
$(TARGET):$(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(TARGET) $(OBJS) $(LDLIBS)

#run:$(OBJS)
#	$(CC) $(CFLAGS) $(LDFLAGS) -o $(TARGET) $(OBJS) $(LDLIBS)
#	./$(TARGET)

clean:
	rm *.o
	rm $(TARGET)
