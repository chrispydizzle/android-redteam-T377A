/* avtab_diag.c - Diagnose and bypass the avtab parse error.
 * Reads the policy up to the avtab, then manually reads avtab entries
 * with a permissive parser that handles Android xperms format. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Read N bytes from file, return 0 on success */
static int read_bytes(FILE *fp, void *buf, size_t n) {
    return fread(buf, 1, n, fp) == n ? 0 : -1;
}

static uint32_t read_u32(FILE *fp) {
    uint32_t v;
    if (fread(&v, 4, 1, fp) != 1) return 0;
    /* Policy uses big-endian (network byte order) */
    return __builtin_bswap32(v);
}

static uint16_t read_u16(FILE *fp) {
    uint16_t v;
    if (fread(&v, 2, 1, fp) != 1) return 0;
    return __builtin_bswap16(v);
}

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "/tmp/sepolicy";
    FILE *fp = fopen(path, "rb");
    if (!fp) { perror("fopen"); return 1; }

    /* Skip to offset where avtab starts. We need to find it by
     * reading through the policy sections. */
    
    /* Read header */
    uint32_t magic = read_u32(fp);
    uint32_t slen = read_u32(fp);
    printf("Magic: 0x%08x, slen: %u\n", magic, slen);
    
    char policystr[32];
    read_bytes(fp, policystr, slen);
    policystr[slen] = 0;
    printf("Policy string: '%s'\n", policystr);
    
    uint32_t version = read_u32(fp);
    uint32_t config = read_u32(fp);
    printf("Version: %u, Config: %u (MLS=%d)\n", version, config, config & 1);
    
    /* Symbol counts */
    uint32_t sym_num = read_u32(fp);
    uint32_t ocon_num = read_u32(fp);
    printf("Sym tables: %u, Ocon tables: %u\n", sym_num, ocon_num);
    
    /* For v20+, symbol tables are interleaved: (nprim, nel, entries)
     * for each of sym_num tables. We need to skip past all of them.
     * Symbols: 0=commons, 1=classes, 2=roles, 3=types, 4=users,
     *          5=booleans, 6=levels, 7=categories */
    
    printf("\nSkipping %u symbol tables to reach avtab...\n", sym_num);
    printf("Position before symbols: %ld (0x%lx)\n", ftell(fp), ftell(fp));
    
    /* Instead of trying to skip each complex section, let me find the
     * avtab by looking for its nel value at a known offset. 
     * Actually, let me use the libsepol approach: read the policy 
     * with libsepol but patch the avtab_read to be permissive. */
    
    fclose(fp);
    
    /* Alternative: directly scan for the avtab nel=29594 pattern */
    fp = fopen(path, "rb");
    uint8_t *data = malloc(773635);
    fread(data, 1, 773635, fp);
    fclose(fp);
    
    /* The avtab nel is 29594 = 0x73AA. In big-endian: 0x00 0x00 0x73 0xAA */
    uint32_t nel_be = 0x0000739A; /* Actually let's search for 29594 in both endians */
    uint32_t target_be = __builtin_bswap32(29594);
    uint32_t target_le = 29594;
    
    printf("\nSearching for avtab nel=29594 (BE=0x%08x LE=0x%08x)...\n", target_be, target_le);
    
    int found = 0;
    for (size_t i = 0; i < 773635 - 4; i++) {
        uint32_t v;
        memcpy(&v, data + i, 4);
        if (v == target_be || v == target_le) {
            printf("  Found at offset %zu (0x%zx): 0x%08x", i, i, v);
            /* Show surrounding context */
            if (i >= 4) {
                uint32_t prev;
                memcpy(&prev, data + i - 4, 4);
                printf("  [prev=0x%08x (%u / %u)]", prev, prev, __builtin_bswap32(prev));
            }
            printf("\n");
            found++;
        }
    }
    
    if (!found) {
        printf("  Not found! Let me search for nearby values...\n");
        for (uint32_t target = 29500; target <= 29700; target++) {
            target_be = __builtin_bswap32(target);
            for (size_t i = 0; i < 773635 - 4; i++) {
                uint32_t v;
                memcpy(&v, data + i, 4);
                if (v == target_be) {
                    if (target >= 29590 && target <= 29598) {
                        printf("  Found %u at offset %zu (0x%zx)\n", target, i, i);
                    }
                }
            }
        }
    }
    
    /* Also search for specific entries near 4823 to find the avtab start */
    /* The avtab starts with nslot (u32) and nel (u32), then nel entries */
    
    /* Each entry (v20+) is: source(u16) + target(u16) + class(u16) + specified(u16) + data
     * For allow/auditallow/dontaudit/transition: + u32 datum
     * For xperms: + u8 specified + u8 driver + u32[8] perms
     * 
     * AVTAB_ALLOWED = 0x0001
     * AVTAB_AUDITALLOW = 0x0002
     * AVTAB_AUDITDENY = 0x0004
     * AVTAB_TRANSITION = 0x0010 (v32+), or 0x0010 in some
     * AVTAB_MEMBER = 0x0020
     * AVTAB_CHANGE = 0x0040
     * AVTAB_XPERMS_ALLOWED = 0x0100
     * AVTAB_XPERMS_AUDITALLOW = 0x0200
     * AVTAB_XPERMS_DONTAUDIT = 0x0400
     */
    
    /* Let me also dump the raw bytes around the problematic area.
     * First, I need to figure out where the avtab starts. 
     * In the libsepol error output, it says "failed on entry 4823 of 29594".
     * If each entry is 12 bytes (8 header + 4 data), the bad entry would be
     * around offset avtab_start + 4 + 4 + 4822*12 from the avtab start.
     * But entries with xperms are larger (8 + 36 = 44 bytes).
     * So we can't easily compute the offset. */
    
    printf("\n--- Hex dump of first 100 bytes at various offsets ---\n");
    
    /* Dump around likely avtab start locations */
    /* The types table should end and then avtab begins. 
     * With 2686 types, the types section is large. Let's look at the 
     * region around offset 60000-70000 where type names start. */
    
    free(data);
    return 0;
}
