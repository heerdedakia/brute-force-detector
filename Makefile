# Works with GNU make on Linux and mingw32-make on Windows.
#   make            build the detector program and all unit tests
#   make test       build and run every unit test
#   make run        build and start the detector
#   make clean
CC     = gcc
CFLAGS = -std=c11 -Wall -Wextra -pedantic -O2 -g

ifeq ($(OS),Windows_NT)
  EXE    = .exe
  NETLIB = -lws2_32
  RM     = del /Q
  RUNPFX =
else
  EXE    =
  NETLIB =
  RM     = rm -f
  RUNPFX = ./
endif

# All backend modules except main.c (shared by the program and the tests)
LIB = backend/deque.c backend/hashtable.c backend/heap.c backend/circular_queue.c backend/linkedlist.c backend/stack.c backend/parser.c backend/detector.c backend/simulator.c backend/baseline.c backend/evaluation.c backend/platform.c backend/json.c backend/app.c backend/api.c backend/server.c
HDR = $(wildcard backend/*.h)
TESTS = test_deque test_hashtable test_heap test_circular_queue test_linkedlist test_stack test_parser test_detector test_simulator test_evaluation test_api test_server
MAIN = backend/main.c

all: $(if $(MAIN),detector$(EXE)) $(addsuffix $(EXE),$(TESTS))

detector$(EXE): $(MAIN) $(LIB) $(HDR)
	$(CC) $(CFLAGS) $(MAIN) $(LIB) -o $@ $(NETLIB)

test_%$(EXE): tests/test_%.c $(LIB) $(HDR)
	$(CC) $(CFLAGS) $< $(LIB) -o $@ $(NETLIB)

test: $(addsuffix $(EXE),$(TESTS))
	$(RUNPFX)test_deque$(EXE)
	$(RUNPFX)test_hashtable$(EXE)
	$(RUNPFX)test_heap$(EXE)
	$(RUNPFX)test_circular_queue$(EXE)
	$(RUNPFX)test_linkedlist$(EXE)
	$(RUNPFX)test_stack$(EXE)
	$(RUNPFX)test_parser$(EXE)
	$(RUNPFX)test_detector$(EXE)
	$(RUNPFX)test_simulator$(EXE)
	$(RUNPFX)test_evaluation$(EXE)
	$(RUNPFX)test_api$(EXE)
	$(RUNPFX)test_server$(EXE)

run: detector$(EXE)
	$(RUNPFX)detector$(EXE)

clean:
	$(RM) test_*$(EXE) detector$(EXE)
