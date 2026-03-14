/* avtab_raw.c - Raw binary reader for Android SELinux avtab entries.
 * Uses libsepol to parse everything BEFORE the avtab, then manually
 * reads the raw avtab bytes to diagnose format issues. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <endian.h>

#define AVTAB_ALLOWED     0x0001
#define AVTAB_AUDITALLOW  0x0002
#define AVTAB_AUDITDENY   0x0004
#define AVTAB_NEVERALLOW  0x0080
#define AVTAB_TRANSITION  0x0010
#define AVTAB_MEMBER      0x0020
#define AVTAB_CHANGE      0x0040
#define AVTAB_XPERMS_ALLOWED     0x0100
#define AVTAB_XPERMS_AUDITALLOW  0x0200
#define AVTAB_XPERMS_DONTAUDIT   0x0400
#define AVTAB_ENABLED     0x8000

static uint32_t ru32(FILE *f) {
    uint32_t v; fread(&v, 4, 1, f); return be32toh(v);
}
static uint16_t ru16(FILE *f) {
    uint16_t v; fread(&v, 2, 1, f); return be16toh(v);
}
static uint8_t ru8(FILE *f) {
    uint8_t v; fread(&v, 1, 1, f); return v;
}

static void skip(FILE *f, size_t n) { fseek(f, n, SEEK_CUR); }

/* Skip a string: read len(u32) + string bytes */
static void skip_string(FILE *f) {
    uint32_t len = ru32(f);
    skip(f, len);
}

/* Skip an ebitmap */
static void skip_ebitmap(FILE *f) {
    uint32_t mapsize = ru32(f);
    uint32_t highbit = ru32(f);
    uint32_t count = ru32(f);
    skip(f, count * (sizeof(uint32_t) + sizeof(uint64_t)));
}

/* Skip a hashtab: nslot(u32) + nel(u32) + entries */
static int skip_hashtab_perms(FILE *f) {
    /* Permission hashtab: each entry is klen(u32) + key + value(u32) */
    uint32_t nprim_unused, nel;
    nprim_unused = ru32(f); /* nprim - ignore, read from parent */
    nel = ru32(f);
    for (uint32_t i = 0; i < nel; i++) {
        uint32_t klen = ru32(f);
        skip(f, klen); /* key */
        ru32(f); /* value */
    }
    return 0;
}

/* Skip constraint expression list */
static void skip_constraints(FILE *f, int ncons) {
    for (int c = 0; c < ncons; c++) {
        uint32_t nexpr = ru32(f);
        for (uint32_t e = 0; e < nexpr; e++) {
            ru32(f); /* expr_type */
            ru32(f); /* attr */
            ru32(f); /* op */
            skip_ebitmap(f); /* names */
            /* v25+: type_names */
            skip_ebitmap(f); /* positives */
            skip_ebitmap(f); /* negatives */
        }
    }
}

/* Skip MLS level */
static void skip_mls_level(FILE *f) {
    ru32(f); /* sens */
    skip_ebitmap(f); /* cat */
}

/* Skip MLS range */
static void skip_mls_range(FILE *f) {
    uint32_t items = ru32(f);
    skip_mls_level(f); /* low */
    if (items > 1)
        skip_mls_level(f); /* high */
}

/* Skip MLS context */
static void skip_context(FILE *f) {
    ru32(f); /* user */
    ru32(f); /* role */
    ru32(f); /* type */
    skip_mls_range(f); /* range */
}

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "/tmp/sepolicy";
    FILE *f = fopen(path, "rb");
    if (!f) { perror("fopen"); return 1; }

    /* === HEADER === */
    uint32_t magic = ru32(f);
    uint32_t slen = ru32(f);
    char pstr[32]; fread(pstr, 1, slen, f); pstr[slen] = 0;
    uint32_t version = ru32(f);
    uint32_t config = ru32(f);
    uint32_t sym_num = ru32(f);
    uint32_t ocon_num = ru32(f);
    int mls = config & 1;

    printf("Header: magic=0x%08x version=%u config=%u(MLS=%d) sym=%u ocon=%u\n",
           magic, version, config, mls, sym_num, ocon_num);
    printf("After header: offset %ld\n", ftell(f));

    /* === SYMBOL TABLES === */
    /* For v20+, each sym table has: nprim(u32) + nel(u32) + entries
     * sym 0: commons
     * sym 1: classes
     * sym 2: roles
     * sym 3: types
     * sym 4: users
     * sym 5: booleans
     * sym 6: levels (if MLS)
     * sym 7: categories (if MLS)
     */
    
    char **type_names = NULL;
    uint32_t ntypes = 0;
    char **class_names = NULL;
    uint32_t nclasses = 0;

    for (uint32_t s = 0; s < sym_num; s++) {
        long pos = ftell(f);
        uint32_t nprim = ru32(f);
        uint32_t nel = ru32(f);
        printf("Sym[%u] at %ld: nprim=%u nel=%u", s, pos, nprim, nel);

        if (s == 0) {
            /* Commons: each entry = klen+key+val+nprim_inner+nel_inner+perms */
            printf(" (commons)\n");
            for (uint32_t i = 0; i < nel; i++) {
                uint32_t klen = ru32(f);
                skip(f, klen); /* key */
                ru32(f); /* value */
                uint32_t cn = ru32(f); /* common nprim */
                uint32_t cnel = ru32(f); /* common nel (perm count) */
                for (uint32_t j = 0; j < cnel; j++) {
                    uint32_t pklen = ru32(f);
                    skip(f, pklen); /* perm key */
                    ru32(f); /* perm value */
                }
            }
        } else if (s == 1) {
            /* Classes: klen+key+comkey_len+comkey+val+nprim_perms+nel_perms+perms+ncons+constraints+nvalcons+valconstraints */
            printf(" (classes)\n");
            class_names = calloc(nprim, sizeof(char *));
            nclasses = nprim;
            for (uint32_t i = 0; i < nel; i++) {
                uint32_t klen = ru32(f);
                char *name = malloc(klen + 1);
                fread(name, 1, klen, f);
                name[klen] = 0;
                
                uint32_t comklen = ru32(f); /* common key length */
                if (comklen > 0) skip(f, comklen); /* common key */
                
                uint32_t val = ru32(f);
                if (val > 0 && val <= nprim) class_names[val - 1] = name;
                else free(name);
                
                /* Class-specific permissions */
                uint32_t cnp = ru32(f); /* nprim for class perms */
                uint32_t cnel = ru32(f); /* nel for class perms */
                for (uint32_t j = 0; j < cnel; j++) {
                    uint32_t pklen = ru32(f);
                    skip(f, pklen);
                    ru32(f);
                }
                
                /* Constraints */
                uint32_t ncons = ru32(f);
                skip_constraints(f, ncons);
                
                /* v19+: validatetrans constraints */
                uint32_t nvalcons = ru32(f);
                skip_constraints(f, nvalcons);

                /* v28+: default_user, default_role, default_range */
                if (version >= 27) {
                    ru32(f); /* default_user */
                    ru32(f); /* default_role */
                }
                if (version >= 28) {
                    ru32(f); /* default_range */
                }
                /* v30+: default_type */
                if (version >= 30) {
                    ru32(f); /* default_type */
                }
            }
        } else if (s == 2) {
            /* Roles: klen+key+val+dominates_ebitmap+v26:types_ebitmap */
            printf(" (roles)\n");
            for (uint32_t i = 0; i < nel; i++) {
                uint32_t klen = ru32(f);
                skip(f, klen);
                ru32(f); /* value */
                skip_ebitmap(f); /* dominates */
                /* v26+: types */
                if (version >= 26) {
                    skip_ebitmap(f);
                }
            }
        } else if (s == 3) {
            /* Types: klen+key+val+primary+flavor(v24+)+bounds(v24+) */
            printf(" (types)\n");
            type_names = calloc(nprim, sizeof(char *));
            ntypes = nprim;
            for (uint32_t i = 0; i < nel; i++) {
                uint32_t klen = ru32(f);
                char *name = malloc(klen + 1);
                fread(name, 1, klen, f);
                name[klen] = 0;
                
                uint32_t val = ru32(f);
                uint32_t primary = ru32(f);
                uint32_t flavor = 0, bounds = 0;
                if (version >= 24) {
                    flavor = ru32(f);
                    bounds = ru32(f);
                }
                
                if (val > 0 && val <= nprim) type_names[val - 1] = name;
                else free(name);
            }
        } else if (s == 4) {
            /* Users: klen+key+val+roles_ebitmap+MLS_range+MLS_dfltlevel */
            printf(" (users)\n");
            for (uint32_t i = 0; i < nel; i++) {
                uint32_t klen = ru32(f);
                skip(f, klen);
                ru32(f); /* value */
                skip_ebitmap(f); /* roles */
                if (mls) {
                    skip_mls_range(f);
                    skip_mls_level(f);
                }
            }
        } else if (s == 5) {
            /* Booleans: klen+key+val+state */
            printf(" (booleans)\n");
            for (uint32_t i = 0; i < nel; i++) {
                uint32_t klen = ru32(f);
                skip(f, klen);
                ru32(f); /* value */
                ru32(f); /* state */
            }
        } else if (s == 6) {
            /* Levels (MLS): klen+key+isalias+level */
            printf(" (levels)\n");
            for (uint32_t i = 0; i < nel; i++) {
                uint32_t klen = ru32(f);
                skip(f, klen);
                ru32(f); /* isalias (really the datum value) */
                skip_mls_level(f);
            }
        } else if (s == 7) {
            /* Categories (MLS): klen+key+val+isalias */
            printf(" (categories)\n");
            for (uint32_t i = 0; i < nel; i++) {
                uint32_t klen = ru32(f);
                skip(f, klen);
                ru32(f); /* value */
                ru32(f); /* isalias */
            }
        }
        printf("  -> end at offset %ld\n", ftell(f));
    }

    /* === AVTAB === */
    long avtab_start = ftell(f);
    uint32_t nel = ru32(f);
    printf("\n=== AVTAB at offset %ld: nel=%u ===\n", avtab_start, nel);

    /* Read entries one by one */
    uint32_t good = 0, bad_spec = 0, xperms_count = 0;
    for (uint32_t i = 0; i < nel; i++) {
        long epos = ftell(f);
        uint16_t src = ru16(f);
        uint16_t tgt = ru16(f);
        uint16_t cls = ru16(f);
        uint16_t spec = ru16(f);

        /* Determine entry data size */
        int is_xperms = (spec & (AVTAB_XPERMS_ALLOWED | AVTAB_XPERMS_AUDITALLOW | AVTAB_XPERMS_DONTAUDIT));
        uint16_t spec_clean = spec & ~AVTAB_ENABLED;
        int popcount = __builtin_popcount(spec_clean);

        if (popcount != 1) {
            printf("ENTRY %u at %ld: src=%u tgt=%u cls=%u spec=0x%04x POPCOUNT=%d **BAD**\n",
                   i, epos, src, tgt, cls, spec, popcount);
            /* Dump next 40 bytes to understand format */
            uint8_t peek[40];
            fread(peek, 1, 40, f);
            printf("  Next 40 bytes:");
            for (int j = 0; j < 40; j++) printf(" %02x", peek[j]);
            printf("\n");
            fseek(f, epos + 8, SEEK_SET); /* Reset to after key */
            
            /* Try to figure out the size: if it looks like xperms, read 34 bytes */
            if (is_xperms) {
                skip(f, 34);
                xperms_count++;
            } else {
                skip(f, 4);
            }
            bad_spec++;
            if (bad_spec >= 20) {
                printf("... stopping after 20 bad entries\n");
                break;
            }
            continue;
        }

        if (is_xperms) {
            ru8(f); /* xperms specified */
            ru8(f); /* driver */
            skip(f, 32); /* perms[8] */
            xperms_count++;
        } else {
            uint32_t data = ru32(f);
            (void)data;
        }
        good++;

        /* Print first few entries to validate */
        if (i < 5) {
            const char *sname = (src > 0 && src <= ntypes && type_names) ? type_names[src-1] : "?";
            const char *tname = (tgt > 0 && tgt <= ntypes && type_names) ? type_names[tgt-1] : "?";
            const char *cname = (cls > 0 && cls <= nclasses && class_names) ? class_names[cls-1] : "?";
            printf("ENTRY %u: %s(%u) -> %s(%u) : %s(%u) spec=0x%04x\n",
                   i, sname, src, tname, tgt, cname, cls, spec);
        }
    }
    
    long end_pos = ftell(f);
    printf("\nAvtab summary: good=%u bad=%u xperms=%u\n", good, bad_spec, xperms_count);
    printf("Avtab end offset: %ld (file size: %ld)\n", end_pos, (long)773635);
    printf("Remaining bytes: %ld\n", 773635 - end_pos);

    /* Cleanup */
    if (type_names) {
        for (uint32_t i = 0; i < ntypes; i++) free(type_names[i]);
        free(type_names);
    }
    if (class_names) {
        for (uint32_t i = 0; i < nclasses; i++) free(class_names[i]);
        free(class_names);
    }
    fclose(f);
    return 0;
}
