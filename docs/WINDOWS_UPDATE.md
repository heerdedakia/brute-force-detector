# CRITICAL UPDATE: WINDOWS-FIRST, C-BASED PROJECT

The entire project must be developed, compiled, tested and executed on Windows 10/11.

This is a strict requirement, not a preference.

## 1. Programming language

All core project functionality MUST be implemented in C11.

This includes:
- Deque using circular arrays.
- Hash table using separate chaining.
- Max heap / priority queue.
- Circular queue.
- Linked lists.
- Login event processing.
- Brute-force detection.
- Threat scoring.
- IP blocking simulation.
- Attack simulation.
- Performance evaluation.
- JSON generation.
- Application control logic.

Do not use Python, C++, Java, Node.js or another language for the detection backend.

HTML, CSS and vanilla JavaScript are allowed ONLY for the dashboard interface.

JavaScript must not duplicate the C detection algorithms.

## 2. Windows compatibility

The project must work natively on Windows 10 and Windows 11.

Use:
- GCC through MinGW-w64 or MSYS2.
- Windows PowerShell.
- VS Code.
- Standard C11 libraries.
- Windows-compatible file paths and commands.

Do NOT require:
- Linux.
- Ubuntu.
- WSL.
- Docker.
- Bash.
- POSIX-only libraries.
- Linux authentication files.
- Linux firewall commands.
- Unix-specific system calls.

Do not use Linux-specific functions such as fork(), inotify(), or sleep() without providing a Windows-compatible implementation.

## 3. Authentication logs

Linux SSH auth.log files may be supported as an optional input format, but the application must NOT depend on them.

The default demonstration must work using simulated authentication events and CSV log files generated locally on Windows.

Example event:

2026-11-20 12:30:15,192.168.1.10,admin,FAILED

The C parser must read this format.

The project must run successfully even if no real server logs are available.

## 4. Windows-compatible IP blocking

Implement a simulated IP blocking system entirely in C.

When an IP exceeds the threat threshold:
1. Add it to the blocklist.
2. Record the blocking timestamp.
3. Calculate its expiry time.
4. Display it in the dashboard.
5. Automatically unblock it when the ban expires.

Do NOT modify the actual Windows Firewall.

Do NOT require administrator privileges.

All blocking must be simulated by default.

## 5. Windows-compatible backend and frontend communication

The C backend must be responsible for generating and updating dashboard data.

Use a lightweight integration architecture.

Preferred approach:

- Compile the C engine into a Windows executable.
- Have the C engine process simulation commands and authentication events.
- Have the C engine produce JSON output.
- Use a minimal Windows-compatible local HTTP server written in C, if required, to serve the frontend and expose API endpoints.
- Use JavaScript fetch() to communicate with the local C application.

Do not use Node.js, Python or another backend runtime.

Do not require the user to manually copy JSON files or repeatedly restart the program to update the dashboard.

The interface should support genuinely working controls such as Start, Pause, Reset, Change Threshold and Unblock.

If using a C HTTP server, keep it simple, localhost-only and explain the Windows Winsock API clearly.

## 6. Build system

Create a Windows build.bat file.

The project should compile using GCC.

Example:

gcc -std=c11 -Wall -Wextra backend/*.c -o detector.exe -lws2_32

Adapt this command to the actual source files and dependencies.

Use the Winsock library only if networking is implemented.

The build script must:
- Compile the application.
- Display useful compiler errors.
- Stop if compilation fails.
- Produce detector.exe.

Also create a run.bat file.

The user should be able to start the project using:

build.bat

run.bat

Do not require Linux commands.

## 7. Windows development testing

Before implementation, inspect the environment.

Check:

gcc --version

where.exe gcc

Test compilation using PowerShell.

If GCC is unavailable, provide exact installation instructions for MinGW-w64 or MSYS2.

Do not claim the project compiles until compilation has actually succeeded.

## 8. Simple code for viva

The C code must be understandable to a college student studying Data Structures.

Use:
- Simple functions.
- Clear variable names.
- Structs.
- Pointers only where necessary.
- Proper comments.
- Modular source files.
- Straightforward control flow.

Avoid:
- Overcomplicated networking.
- Unnecessary multithreading.
- Advanced pointer manipulation.
- Complex build systems.
- Excessive dependencies.

Explain all Windows-specific functions used.

## 9. UI requirements remain unchanged

Create a polished, interactive, dark-themed cybersecurity dashboard.

Use:
- Dark charcoal/navy colors.
- Subtle blue accents.
- Clean tables.
- Interactive charts.
- Professional typography.
- Responsive layout.
- Minimal animations.

The UI must not look like a generic AI-generated template.

All important controls must work with the actual C backend.

## 10. Final Windows execution requirement

The completed project must be runnable on Windows using:

1. Open project in VS Code.
2. Open PowerShell terminal.
3. Run build.bat.
4. Run run.bat.
5. Open http://localhost:8080 in a browser.
6. Use the interactive dashboard.
7. Start simulated attacks.
8. Observe the C detection engine identify suspicious IPs.
9. View threat rankings and temporary blocks.
10. View actual performance results.

Port 8080 is the intended default; use another available local port if necessary and print the correct URL.

No Linux installation, WSL, Docker or additional backend runtime should be required.

IMPORTANT:

Do not just claim Windows compatibility.

Actually compile, run and test the project on Windows if the execution environment permits it.

If you are not running on Windows, explicitly state that native Windows testing remains unverified.

The project must remain a genuine C-based DSA Engineering Lab project, not a JavaScript application pretending to use C.

These requirements override any earlier Linux-specific or conflicting instructions.

Now continue development using this Windows-first architecture.