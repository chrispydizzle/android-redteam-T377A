/* avtab_override.c - Override libsepol's avtab_read with a version that
 * skips entries with unrecognized specifier values instead of failing.
 * Link this BEFORE libsepol.a to override the symbols. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/avtab.h>

/* Copied from libsepol internals */
#define le16_to_cpu(x) le16toh(x)
#define le32_to_cpu(x) le32toh(x)

static int next_entry(void *buf, struct policy_file *fp, size_t bytes)
{
    size_t nread;
    switch (fp->type) {
    case PF_USE_STDIO:
        nread = fread(buf, bytes, 1, fp->fp);
        if (nread != 1) return -1;
        break;
    case PF_USE_MEMORY:
        if (fp->len < bytes) return -1;
        memcpy(buf, fp->data, bytes);
        fp->data += bytes;
        fp->len -= bytes;
        break;
    default:
        return -1;
    }
    return 0;
}

/* Our permissive version of avtab_read_item */
int avtab_read_item(struct policy_file *fp, uint32_t vers, avtab_t *a,
    int (*insertf)(avtab_t *a, avtab_key_t *k, avtab_datum_t *d, void *p),
    void *p)
{
    uint16_t buf16[4];
    uint32_t buf32[9]; /* 1 for data or 8+1 for xperms */
    uint8_t buf8;
    avtab_key_t key;
    avtab_datum_t datum;
    avtab_extended_perms_t xperms;
    unsigned int i;
    int rc;

    memset(&key, 0, sizeof(key));
    memset(&datum, 0, sizeof(datum));
    memset(&xperms, 0, sizeof(xperms));

    /* For policy version < 20 (POLICYDB_VERSION_AVTAB), old format applies.
     * Our policy is v30, so we always use the new format. */
    if (vers < 20) {
        /* Old format: 4 u32 values + data */
        rc = next_entry(buf32, fp, sizeof(uint32_t) * 4);
        if (rc < 0) return -1;

        uint32_t items2 = le32_to_cpu(buf32[0]);
        uint32_t val = le32_to_cpu(buf32[1]);

        key.source_type = (uint16_t)le32_to_cpu(buf32[0]);
        key.target_type = (uint16_t)le32_to_cpu(buf32[1]);
        key.target_class = (uint16_t)le32_to_cpu(buf32[2]);

        /* Old format encodes specified as a bitmask with potentially
         * multiple bits set. Split into individual rules. */
        uint32_t specified = le32_to_cpu(buf32[3]);

        /* Read the remaining data for each specified bit */
        int items_count = __builtin_popcount(specified);
        for (i = 0; i < (unsigned)items_count; i++) {
            rc = next_entry(buf32, fp, sizeof(uint32_t));
            if (rc < 0) return -1;
        }
        /* Just skip old format entries */
        return 0;
    }

    /* New format (v20+): 4 u16 values */
    rc = next_entry(buf16, fp, sizeof(uint16_t) * 4);
    if (rc < 0) return -1;

    key.source_type = le16_to_cpu(buf16[0]);
    key.target_type = le16_to_cpu(buf16[1]);
    key.target_class = le16_to_cpu(buf16[2]);
    key.specified = le16_to_cpu(buf16[3]);

    /* Check for xperms entries */
    if (key.specified & AVTAB_XPERMS) {
        /* Read xperms data: u8 specified + u8 driver + 8 u32 perms */
        rc = next_entry(&buf8, fp, sizeof(uint8_t));
        if (rc < 0) return -1;
        xperms.specified = buf8;

        rc = next_entry(&buf8, fp, sizeof(uint8_t));
        if (rc < 0) return -1;
        xperms.driver = buf8;

        rc = next_entry(buf32, fp, sizeof(uint32_t) * 8);
        if (rc < 0) return -1;
        for (i = 0; i < 8; i++)
            xperms.perms[i] = le32_to_cpu(buf32[i]);

        datum.xperms = &xperms;
    } else {
        /* Regular entry: 1 u32 data value */
        rc = next_entry(buf32, fp, sizeof(uint32_t));
        if (rc < 0) return -1;
        datum.data = le32_to_cpu(buf32[0]);
    }

    /* Validate specifier — but DON'T fail, just skip */
    uint16_t spec_clean = key.specified & ~AVTAB_ENABLED;
    if (spec_clean == 0 || __builtin_popcount(spec_clean) > 1) {
        /* Bad entry — skip it silently */
        return 0;
    }

    /* Check for valid non-xperms specifiers */
    if (!(key.specified & (AVTAB_AV | AVTAB_TYPE | AVTAB_XPERMS))) {
        /* Unknown specifier — skip */
        return 0;
    }

    /* Insert into avtab */
    if (insertf) {
        rc = insertf(a, &key, &datum, p);
        if (rc) return rc;
    }

    return 0;
}

static int my_insertf(avtab_t *a, avtab_key_t *k, avtab_datum_t *d,
                      void *p __attribute__((unused)))
{
    return avtab_insert(a, k, d);
}

int avtab_read(avtab_t *a, struct policy_file *fp, uint32_t vers)
{
    unsigned int i;
    int rc;
    uint32_t buf[1];
    uint32_t nel;
    unsigned int skipped = 0;

    rc = next_entry(buf, fp, sizeof(uint32_t));
    if (rc < 0) {
        fprintf(stderr, "avtab_read: truncated table\n");
        return -1;
    }
    nel = le32_to_cpu(buf[0]);
    fprintf(stderr, "avtab_read: nel=%u\n", nel);

    if (nel == 0) return 0;

    rc = avtab_alloc(a, nel);
    if (rc) {
        fprintf(stderr, "avtab_read: out of memory\n");
        return -1;
    }

    for (i = 0; i < nel; i++) {
        rc = avtab_read_item(fp, vers, a, my_insertf, NULL);
        if (rc) {
            fprintf(stderr, "avtab_read: error on entry %d of %u, skipping rest\n", i, nel);
            skipped = nel - i;
            break;
        }
    }

    fprintf(stderr, "avtab_read: loaded %u entries, skipped %u\n", i - skipped, skipped);
    return 0;
}
