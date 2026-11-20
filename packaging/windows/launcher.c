/* TraceQuarry portable launcher.
 *
 * Runs "<dir>\runtime\python.exe <dir>\app\<script> <args...>" and returns its
 * exit code. The script name is selected at compile time with -DTQ_SCRIPT.
 * Build: x86_64-w64-mingw32-gcc -O2 -municode -DTQ_SCRIPT=L"launcher.py" ...
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <wchar.h>

#ifndef TQ_SCRIPT
#define TQ_SCRIPT L"launcher.py"
#endif
#ifndef TQ_PAUSE_ON_ERROR
#define TQ_PAUSE_ON_ERROR 1
#endif

static const wchar_t *skip_program_name(const wchar_t *cmd) {
    if (*cmd == L'"') {
        cmd++;
        while (*cmd && *cmd != L'"') cmd++;
        if (*cmd) cmd++;
    } else {
        while (*cmd && *cmd != L' ' && *cmd != L'\t') cmd++;
    }
    while (*cmd == L' ' || *cmd == L'\t') cmd++;
    return cmd;
}

static void pause_if_own_console(void) {
    DWORD processes[2];
    if (TQ_PAUSE_ON_ERROR && GetConsoleProcessList(processes, 2) <= 1) {
        HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
        DWORD read = 0;
        wchar_t buffer[8];
        fwprintf(stderr, L"\nPress Enter to close this window.\n");
        /* Keys typed while the server was running must not answer this prompt. */
        FlushConsoleInputBuffer(input);
        ReadConsoleW(input, buffer, 1, &read, NULL);
    }
}

int wmain(void) {
    static wchar_t dir[32768], command[65536];
    DWORD length = GetModuleFileNameW(NULL, dir, 32768);
    if (length == 0 || length >= 32768) {
        fwprintf(stderr, L"TraceQuarry: unable to locate the program directory.\n");
        pause_if_own_console();
        return 1;
    }
    wchar_t *slash = wcsrchr(dir, L'\\');
    if (slash) *slash = 0;

    const wchar_t *arguments = skip_program_name(GetCommandLineW());
    int written = _snwprintf(command, 65536,
                             L"\"%ls\\runtime\\python.exe\" \"%ls\\app\\%ls\" %ls",
                             dir, dir, TQ_SCRIPT, arguments);
    if (written < 0 || written >= 65536) {
        fwprintf(stderr, L"TraceQuarry: command line is too long.\n");
        pause_if_own_console();
        return 1;
    }

    STARTUPINFOW startup;
    PROCESS_INFORMATION process;
    ZeroMemory(&startup, sizeof startup);
    startup.cb = sizeof startup;
    SetConsoleCtrlHandler(NULL, TRUE); /* let the child handle Ctrl+C */
    if (!CreateProcessW(NULL, command, NULL, NULL, TRUE, 0, NULL, NULL, &startup, &process)) {
        fwprintf(stderr,
                 L"TraceQuarry: unable to start runtime\\python.exe (error %lu).\n"
                 L"Extract the whole ZIP before running, and keep the folder structure intact.\n",
                 GetLastError());
        pause_if_own_console();
        return 1;
    }
    WaitForSingleObject(process.hProcess, INFINITE);
    DWORD exit_code = 1;
    GetExitCodeProcess(process.hProcess, &exit_code);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    if (exit_code != 0 && exit_code != 0xC000013A) {
        fwprintf(stderr, L"\nTraceQuarry stopped unexpectedly (exit code 0x%08lX).\n"
                         L"Details are in data\\logs.\n", exit_code);
        pause_if_own_console();
    }
    return (int)exit_code;
}
