EXECUTABLE=hsmperf

.PHONY: all clean

all:
	 $(CC) $(EXECUTABLE).c -o $(EXECUTABLE) -ldl -lrt

clean:
	rm -f $(EXECUTABLE)
