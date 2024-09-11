#include <stdint.h>
#include <HYPEREYE_defs.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#define TEST_IOCTL_RET(x) if (x) return EXIT_FAILURE;

#define PAGE_SIZE               0x1000

#define CONFIG_FILE             "qemu.config"

#define QEMU_MONITOR_STRING     " -monitor unix:$(pwd)/monitor,server,nowait"
#define QEMU_DEBUG_STRING       " -gdb tcp::9000"

#define QEMU_WAIT               "while ! sshpass -p \'%s\' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=2 %s@localhost -p 5555 \"ls\" do echo \"Trying again...\" done"

#define QEMU_MEM_FILE           "mem.bin"

#define QEMU_MEM_DUMP_CMD       "echo \"pmemsave 0x0 0x100000 " QEMU_MEM_FILE "\" | socat - unix-connect:$(pwd)/monitor"
#define QEMU_MEM_INFO_CMD       "echo \"info mem\" | socat - unix-connect:$(pwd)/monitor"

#define SCP_TRANSFER_FILE       "scp -P 5555 "
#define SSH_REMOTE              "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=2 %s@localhost -p 5555"

int load_config_file(char** username, char** pswd, char** qemu_cmd, char** compile_cmd, char** stub_local_path, char** stub_remote_path, uint64_t* guest_memory_amount) {
    FILE*           fp;
    char *          line = NULL;
    size_t          len = 0;
    size_t          cpy_len;
    ssize_t         read;
    int             err = 0;
    char*           vmem = NULL;

    fp = fopen(CONFIG_FILE, "r");
	if (fp == NULL) {
		printf("Cannot open %s\n", CONFIG_FILE);
		return -1;
	}

    while ((read = getline(&line, &len, fp)) != -1) {
        cpy_len = strlen(line) - 6;

        // Config variable should not be empty
        if (cpy_len > 0) {
            if (strstr(line, "$user=") == line) {
                *username = malloc(cpy_len);
                memcpy(*username, line+6, cpy_len);
                // Only remove the last char if it is a new line character. The last line in the file
                // might not end with a new line.
                if (*(char*)(*username + cpy_len - 1) == 0xa) *(char*)(*username + cpy_len - 1) = 0x0;
            }
            if (strstr(line, "$pswd=") == line) {
                *pswd = malloc(cpy_len);
                memcpy(*pswd, line+6, cpy_len);
                if (*(char*)(*pswd + cpy_len - 1) == 0xa) *(char*)(*pswd + cpy_len - 1) = 0x0;
            }
            if (strstr(line, "$qcmd=") == line) {
                *qemu_cmd = malloc(cpy_len);
                memcpy(*qemu_cmd, line+6, cpy_len);
                if (*(char*)(*qemu_cmd + cpy_len - 1) == 0xa) *(char*)(*qemu_cmd + cpy_len - 1) = 0x0;
            }
            if (strstr(line, "$ccmd=") == line) {
                *compile_cmd = malloc(cpy_len);
                memcpy(*compile_cmd, line+6, cpy_len);
                if (*(char*)(*compile_cmd + cpy_len - 1) == 0xa) *(char*)(*compile_cmd + cpy_len - 1) = 0x0;
            }
            if (strstr(line, "$slph=") == line) {
                *stub_local_path = malloc(cpy_len);
                memcpy(*stub_local_path, line+6, cpy_len);
                if (*(char*)(*stub_local_path + cpy_len - 1) == 0xa) *(char*)(*stub_local_path + cpy_len - 1) = 0x0;
            }
            if (strstr(line, "$srph=") == line) {
                *stub_remote_path = malloc(cpy_len);
                memcpy(*stub_remote_path, line+6, cpy_len);
                if (*(char*)(*stub_remote_path + cpy_len - 1) == 0xa) *(char*)(*stub_remote_path + cpy_len - 1) = 0x0;
            }
            if (strstr(line, "$vmem=") == line) {
                vmem = malloc(cpy_len);
                memcpy(vmem, line+6, cpy_len);
                if (*(char*)(vmem + cpy_len - 1) == 0xa) *(char*)(vmem + cpy_len - 1) = 0x0;
                *guest_memory_amount = (uint64_t)strtol(vmem, NULL, 16);
            }
        } else {
            printf("Empty config variable: %s\n", line);
            err = -1;
            goto err;
        }
    }

    // Check if we read in all variables
    if (*username == NULL || *pswd == NULL || *qemu_cmd == NULL) {
        printf("Not all needed variables in config file!\n");

        if (*username == NULL)  free(*username);
        if (*pswd == NULL)      free(*pswd);
        if (*qemu_cmd == NULL)  free(*qemu_cmd);

        err = -1;
        goto err;
    }

err:
    fclose(fp);

    return 0;
}

int stop_qemu() {
    if (system("echo \"stop\" | socat - unix-connect:$(pwd)/monitor") != EXIT_SUCCESS) {
        return -1;
    }

    return 0;
}

int cont_qemu() {
    if (system("echo \"cont\" | socat - unix-connect:$(pwd)/monitor") != EXIT_SUCCESS) {
        return -1;
    }

    return 0;
}

int wait_for_ssh(char* username, char* pswd) {
    char*   qemu_wait;

    qemu_wait = malloc(strlen(QEMU_WAIT) + strlen(username) + strlen(pswd));
    sprintf(qemu_wait, QEMU_WAIT, username, pswd);

    if (system(qemu_wait) != EXIT_SUCCESS) {
        free(qemu_wait);
        return -1;
    }

    free(qemu_wait);
    return 0;
}

int dump_qemu_mem() {
    if (system(QEMU_MEM_DUMP_CMD) != EXIT_SUCCESS) {
        return -1;
    }

    return 0;
} 

int setup_guest_stub(char* username, char* pswd, char* compile_cmd, char* stub_local_path, char* stub_remote_path, char* sshpass) {
    char* scp_cmd;
    char* run_cmd;
    char* ssh;

    // First, compile the syscall stub
    if (system(compile_cmd) != EXIT_SUCCESS) {
        return -1;
    }

    // Next, transfer the stub to the guest
    scp_cmd = malloc(strlen(sshpass) + strlen(SCP_TRANSFER_FILE) + strlen(username) + 1 + strlen("localhost:") + strlen(stub_local_path) + 1 + strlen(stub_remote_path));
    memcpy(scp_cmd, sshpass, strlen(sshpass));
    strcat(scp_cmd, SCP_TRANSFER_FILE);
    strcat(scp_cmd, username);
    strcat(scp_cmd, "@");
    strcat(scp_cmd, "localhost:");
    strcat(scp_cmd, stub_local_path);
    strcat(scp_cmd, stub_remote_path);

    printf("Executing scp command: %s\n", scp_cmd);

    if (system(scp_cmd) != EXIT_SUCCESS) {
        return -1;
    }

    // Finally, run the command in the guest
    ssh = malloc(strlen(SSH_REMOTE) + strlen(username));
    sprintf(ssh, SSH_REMOTE, username);

    run_cmd = malloc(strlen(sshpass) + strlen(ssh) + strlen(stub_remote_path) + 3);
    memcpy(run_cmd, sshpass, strlen(sshpass));
    strcat(run_cmd, ssh);
    strcat(run_cmd, "\"");
    strcat(run_cmd, stub_remote_path);
    strcat(run_cmd, "\"");

    printf("Executing ssh run command: %s\n", run_cmd);

    if (system(run_cmd) != EXIT_SUCCESS) {
        return -1;
    }

    return 0;
}

// Tell HYPEREYE to create a guest from the KVM trace
int64_t create_HYPEREYE_fuzzing_guest(int ctl_fd) {
    uint64_t    guest_id = GUEST_CREATE_KVM_REC;

    TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_IOCTL_CREATE_GUEST, &guest_id))

    return guest_id;
}

int load_qemu_memory_state(int ctl_fd, uint64_t guest_memory_amount, uint64_t** guest_mem) {
    uint64_t    current_addr;
    int         qemu_mem_fd;

    guest_mem = mmap(NULL, guest_memory_amount, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    qemu_mem_fd = open(QEMU_MEM_FILE, O_RDWR);
	if (qemu_mem_fd == -1) {
		printf("Could not open " QEMU_MEM_FILE "\n");
		return -1;
	}

    for (current_addr = 0; current_addr < guest_memory_amount; current_addr += PAGE_SIZE) {
        if (read(qemu_mem_fd, (void*)((uint64_t)(guest_mem) + current_addr), PAGE_SIZE) == -1) {
            return -1;
        }
    }

    close(qemu_mem_fd);

    return 0;
}

int main(int argc, char** argv) {
    int			ctl_fd;
    char*       username;
    char*       pswd;
    char*       qemu_cmd;
    char*       compile_cmd;
    char*       stub_local_path;
    char*       stub_remote_path;
    uint64_t    guest_memory_amount;
    char*       sshpass;

    uint64_t    guest_id;
    void*       guest_mem;

    ctl_fd = open(HYPEREYE_PROC_PATH, O_RDWR);
	if (ctl_fd == -1) {
		printf("Could not open " HYPEREYE_PROC_PATH "\n");
		return EXIT_FAILURE;
	}

    if (load_config_file(&username, &pswd, &qemu_cmd, &compile_cmd, &stub_local_path, &stub_remote_path, &guest_memory_amount)) {
        return EXIT_FAILURE;
    }

    printf("Loaded configuration:\n");
    printf("\tusername: %s\n", username);
    printf("\tpswd: %s\n", pswd);
    printf("\tqemu_cmd: %s\n", qemu_cmd);
    printf("\tstub_local_path: %s\n", stub_local_path);
    printf("\tstub_remote_path: %s\n", stub_remote_path);
    printf("\tguest memory amount in bytes: 0x%lx\n", guest_memory_amount);

    // Prepare the sshpass string
    sshpass = malloc(strlen("sshpass -p \'") + strlen(pswd) + 1);
    memcpy(sshpass, "sshpass -p \'", strlen("sshpass -p \'"));
    strcat(sshpass, pswd);
    strcat(sshpass, "\'");

    // Run the QEMU command
    qemu_cmd = realloc(qemu_cmd, strlen(qemu_cmd) + strlen(QEMU_MONITOR_STRING));
    strcat (qemu_cmd, QEMU_MONITOR_STRING);
    printf("Starting QEMU...");
    if (system(qemu_cmd) != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }

    // Register the KVM tracing in HYPEREYE
    if (stop_qemu()) return EXIT_FAILURE;
    TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_BEGIN_KVM_RECORD,NULL))
    if (cont_qemu()) return EXIT_FAILURE;

    // Wait until the QEMU host is booted and we can ssh into it
    wait_for_ssh(username, pswd);

    // Run the syscall stub in the guest
    if (setup_guest_stub(username, pswd, compile_cmd, stub_local_path, stub_remote_path, sshpass)) return EXIT_FAILURE;

    // Wait for the stub to be actually executed
    sleep(1);

    // Continue until stub passes execution into the kernel: Wait until we are in kernel syscall handler context of
    // the stub
    if (system("gdb wait_for_stub.gdb") != EXIT_SUCCESS) {
        return -1;
    }
    stop_qemu();
    TEST_IOCTL_RET(ioctl(ctl_fd, HYPEREYE_END_KVM_RECORD, NULL))

    // Dump QEMU memory
    printf("Dumping QEMU memory to file\n");
    if (dump_qemu_mem()) return EXIT_FAILURE;

    // Now create the HYPEREYE guest with all loaded parameters
    printf("Create HYPEREYE guest\n");
    guest_id = create_HYPEREYE_fuzzing_guest(ctl_fd);

    // Load the QEMU memory dump into HYPEREYE
    load_qemu_memory_state(ctl_fd, guest_memory_amount, (uint64_t**)&guest_mem);

    close(ctl_fd);

    return EXIT_SUCCESS;
}