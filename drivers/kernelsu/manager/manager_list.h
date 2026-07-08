#ifndef __MANAGER_LIST_H
#define __MANAGER_LIST_H

struct manager_identity {
    const char *package_name;
    const char *hash;
    const uint32_t sig_size;
};

static const struct manager_identity allowed_managers[] = {
    {
        .package_name = "com.rifsxd.ksunext", // KernelSU-Next
        .hash = "79e590113c4c4c0c222978e413a5faa801666957b1212a328e46c00c69821bf7", 
        .sig_size = 0x3e6
    },
    {
        .package_name = "vctsrt.cntgtj.uqfwgg", // KernelSU-Next Spoof
        .hash = "79e590113c4c4c0c222978e413a5faa801666957b1212a328e46c00c69821bf7", 
        .sig_size = 0x3e6
    },
    {
        .package_name = "id.i.bi", // Next Manager Spoof
        .hash = "1ab6077099505a4f5ff851732d5d965a4908af7f60c871f23b4b3a58e80e6cd3",
        .sig_size = 0x31c
    },
    {
        .package_name = "id.next.manager", // Next Manager
        .hash = "1ab6077099505a4f5ff851732d5d965a4908af7f60c871f23b4b3a58e80e6cd3",
        .sig_size = 0x31c
    }
};

#endif
