/* sepol_dump.c - Dump Android SELinux policy using libsepol internals.
 * Ignores avtab read errors and dumps type/class/transition data. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/services.h>
#include <sepol/policydb/avtab.h>
#include <sepol/policydb/conditional.h>

static int dump_type(hashtab_key_t key, hashtab_datum_t datum, void *args) {
    type_datum_t *td = (type_datum_t *)datum;
    const char *flavor = td->flavor == TYPE_TYPE ? "type" :
                         td->flavor == TYPE_ATTRIB ? "attr" : "alias";
    printf("  [%4u] %-6s %s%s\n", td->s.value, flavor, key,
           td->flags & TYPE_FLAGS_PERMISSIVE ? " (PERMISSIVE!)" : "");
    return 0;
}

static int dump_class(hashtab_key_t key, hashtab_datum_t datum, void *args) {
    class_datum_t *cd = (class_datum_t *)datum;
    printf("  [%4u] %s (perms: %u)\n", cd->s.value, key,
           cd->permissions.nprim);
    return 0;
}

static int dump_common(hashtab_key_t key, hashtab_datum_t datum, void *args) {
    common_datum_t *cd = (common_datum_t *)datum;
    printf("  [%4u] %s (perms: %u)\n", cd->s.value, key,
           cd->permissions.nprim);
    return 0;
}

/* Find type value by name */
static uint32_t find_type(policydb_t *p, const char *name) {
    type_datum_t *td = hashtab_search(p->p_types.table, (hashtab_key_t)name);
    return td ? td->s.value : 0;
}

/* Get type name by value */
static const char *type_name(policydb_t *p, uint32_t val) {
    if (val > 0 && val <= p->p_types.nprim)
        return p->p_type_val_to_name[val - 1];
    return "???";
}

/* Get class name by value */
static const char *class_name(policydb_t *p, uint32_t val) {
    if (val > 0 && val <= p->p_classes.nprim)
        return p->p_class_val_to_name[val - 1];
    return "???";
}

/* Get permission name from class+bit */
static void perm_name(policydb_t *p, uint32_t class_val, uint32_t perm_bit,
                      char *buf, int bufsz) {
    class_datum_t *cladatum;
    if (class_val > 0 && class_val <= p->p_classes.nprim) {
        cladatum = p->class_val_to_struct[class_val - 1];
        if (cladatum) {
            /* Search common perms first */
            if (cladatum->comdatum) {
                hashtab_t h = cladatum->comdatum->permissions.table;
                unsigned int i;
                for (i = 0; i < h->size; i++) {
                    hashtab_node_t *cur;
                    for (cur = h->htable[i]; cur; cur = cur->next) {
                        perm_datum_t *pd = (perm_datum_t *)cur->datum;
                        if (pd->s.value == perm_bit) {
                            snprintf(buf, bufsz, "%s", (char *)cur->key);
                            return;
                        }
                    }
                }
            }
            /* Search class-specific perms */
            hashtab_t h = cladatum->permissions.table;
            unsigned int i;
            for (i = 0; i < h->size; i++) {
                hashtab_node_t *cur;
                for (cur = h->htable[i]; cur; cur = cur->next) {
                    perm_datum_t *pd = (perm_datum_t *)cur->datum;
                    if (pd->s.value == perm_bit) {
                        snprintf(buf, bufsz, "%s", (char *)cur->key);
                        return;
                    }
                }
            }
        }
    }
    snprintf(buf, bufsz, "perm_%u", perm_bit);
}

static void dump_perms(policydb_t *p, uint32_t class_val, uint32_t perms) {
    int bit;
    char pbuf[64];
    for (bit = 0; bit < 32; bit++) {
        if (perms & (1 << bit)) {
            perm_name(p, class_val, bit + 1, pbuf, sizeof(pbuf));
            printf(" %s", pbuf);
        }
    }
}

/* Dump allow rules for a source type */
static void dump_allow_for(policydb_t *p, const char *src_name) {
    uint32_t src = find_type(p, src_name);
    if (!src) { printf("  Type '%s' not found\n", src_name); return; }
    
    avtab_t *a = &p->te_avtab;
    unsigned int i;
    int count = 0;
    for (i = 0; i < a->nslot; i++) {
        avtab_ptr_t cur;
        for (cur = a->htable[i]; cur; cur = cur->next) {
            if (cur->key.source_type == src &&
                cur->key.specified & AVTAB_ALLOWED) {
                printf("  allow %s %s:%s {", src_name,
                       type_name(p, cur->key.target_type),
                       class_name(p, cur->key.target_class));
                dump_perms(p, cur->key.target_class, cur->datum.data);
                printf(" };\n");
                count++;
            }
        }
    }
    /* Also check conditional rules */
    cond_list_t *cond;
    for (cond = p->cond_list; cond; cond = cond->next) {
        cond_av_list_t *avl;
        for (avl = cond->true_list; avl; avl = avl->next) {
            avtab_ptr_t node = avl->node;
            if (node->key.source_type == src &&
                node->key.specified & AVTAB_ALLOWED) {
                printf("  allow %s %s:%s {", src_name,
                       type_name(p, node->key.target_type),
                       class_name(p, node->key.target_class));
                dump_perms(p, node->key.target_class, node->datum.data);
                printf(" }; [conditional]\n");
                count++;
            }
        }
        for (avl = cond->false_list; avl; avl = avl->next) {
            avtab_ptr_t node = avl->node;
            if (node->key.source_type == src &&
                node->key.specified & AVTAB_ALLOWED) {
                printf("  allow %s %s:%s {", src_name,
                       type_name(p, node->key.target_type),
                       class_name(p, node->key.target_class));
                dump_perms(p, node->key.target_class, node->datum.data);
                printf(" }; [conditional]\n");
                count++;
            }
        }
    }
    printf("  (%d allow rules)\n", count);
}

/* Dump type transitions for a source type */
static void dump_transitions_for(policydb_t *p, const char *src_name) {
    uint32_t src = find_type(p, src_name);
    if (!src) { printf("  Type '%s' not found\n", src_name); return; }
    
    avtab_t *a = &p->te_avtab;
    unsigned int i;
    int count = 0;
    for (i = 0; i < a->nslot; i++) {
        avtab_ptr_t cur;
        for (cur = a->htable[i]; cur; cur = cur->next) {
            if (cur->key.source_type == src &&
                cur->key.specified & AVTAB_TRANSITION) {
                printf("  type_transition %s %s:%s %s;\n", src_name,
                       type_name(p, cur->key.target_type),
                       class_name(p, cur->key.target_class),
                       type_name(p, cur->datum.data));
                count++;
            }
        }
    }
    printf("  (%d transitions)\n", count);
}

/* Dump transitions TO a target default type */
static void dump_transitions_to(policydb_t *p, const char *dflt_name) {
    uint32_t dflt = find_type(p, dflt_name);
    if (!dflt) { printf("  Type '%s' not found\n", dflt_name); return; }
    
    avtab_t *a = &p->te_avtab;
    unsigned int i;
    int count = 0;
    for (i = 0; i < a->nslot; i++) {
        avtab_ptr_t cur;
        for (cur = a->htable[i]; cur; cur = cur->next) {
            if (cur->key.specified & AVTAB_TRANSITION &&
                cur->datum.data == dflt) {
                printf("  type_transition %s %s:%s %s;\n",
                       type_name(p, cur->key.source_type),
                       type_name(p, cur->key.target_type),
                       class_name(p, cur->key.target_class),
                       dflt_name);
                count++;
            }
        }
    }
    printf("  (%d transitions)\n", count);
}

int main(int argc, char **argv) {
    const char *policy_file = argc > 1 ? argv[1] : "/tmp/sepolicy";
    FILE *fp;
    policydb_t pdb;
    struct policy_file pf;
    int rc;

    fp = fopen(policy_file, "rb");
    if (!fp) { perror("fopen"); return 1; }

    if (policydb_init(&pdb)) {
        fprintf(stderr, "policydb_init failed\n");
        return 1;
    }

    policy_file_init(&pf);
    pf.type = PF_USE_STDIO;
    pf.fp = fp;

    rc = policydb_read(&pdb, &pf, 0);
    fclose(fp);

    if (rc) {
        fprintf(stderr, "WARNING: policydb_read returned %d (partial parse may still work)\n", rc);
        /* Continue anyway — types/classes may be populated */
    }

    printf("Policy version: %u\n", pdb.policyvers);
    printf("Types: %u\n", pdb.p_types.nprim);
    printf("Classes: %u\n", pdb.p_classes.nprim);
    printf("Roles: %u\n", pdb.p_roles.nprim);

    /* If policydb_read failed, the index arrays won't be built.
     * Build them manually. policydb_index_others builds p_type_val_to_name etc. */
    if (rc && pdb.p_types.nprim > 0) {
        fprintf(stderr, "Attempting manual index build...\n");
        /* Allocate reverse-mapping arrays */
        pdb.p_type_val_to_name = calloc(pdb.p_types.nprim, sizeof(char *));
        pdb.type_val_to_struct = calloc(pdb.p_types.nprim, sizeof(type_datum_t *));
        pdb.p_class_val_to_name = calloc(pdb.p_classes.nprim, sizeof(char *));
        pdb.class_val_to_struct = calloc(pdb.p_classes.nprim, sizeof(class_datum_t *));
        pdb.p_role_val_to_name = calloc(pdb.p_roles.nprim, sizeof(char *));
        
        /* Populate type mappings from hashtab */
        if (pdb.p_types.table) {
            unsigned int i;
            for (i = 0; i < pdb.p_types.table->size; i++) {
                hashtab_node_t *cur;
                for (cur = pdb.p_types.table->htable[i]; cur; cur = cur->next) {
                    type_datum_t *td = (type_datum_t *)cur->datum;
                    if (td->s.value > 0 && td->s.value <= pdb.p_types.nprim) {
                        pdb.p_type_val_to_name[td->s.value - 1] = cur->key;
                        pdb.type_val_to_struct[td->s.value - 1] = td;
                    }
                }
            }
            fprintf(stderr, "Type reverse-map built\n");
        }
        /* Populate class mappings */
        if (pdb.p_classes.table) {
            unsigned int i;
            for (i = 0; i < pdb.p_classes.table->size; i++) {
                hashtab_node_t *cur;
                for (cur = pdb.p_classes.table->htable[i]; cur; cur = cur->next) {
                    class_datum_t *cd = (class_datum_t *)cur->datum;
                    if (cd->s.value > 0 && cd->s.value <= pdb.p_classes.nprim) {
                        pdb.p_class_val_to_name[cd->s.value - 1] = cur->key;
                        pdb.class_val_to_struct[cd->s.value - 1] = cd;
                    }
                }
            }
            fprintf(stderr, "Class reverse-map built\n");
        }
        /* Populate role mappings */
        if (pdb.p_roles.table) {
            unsigned int i;
            for (i = 0; i < pdb.p_roles.table->size; i++) {
                hashtab_node_t *cur;
                for (cur = pdb.p_roles.table->htable[i]; cur; cur = cur->next) {
                    role_datum_t *rd = (role_datum_t *)cur->datum;
                    if (rd->s.value > 0 && rd->s.value <= pdb.p_roles.nprim) {
                        pdb.p_role_val_to_name[rd->s.value - 1] = cur->key;
                    }
                }
            }
        }
    }

    /* Check if types table is populated */
    if (pdb.p_types.nprim == 0 || !pdb.p_type_val_to_name) {
        fprintf(stderr, "Types table not populated - partial parse failed\n");
        policydb_destroy(&pdb);
        return 1;
    }

    /* === PERMISSIVE TYPES === */
    printf("\n======= 1. PERMISSIVE TYPES =======\n");
    {
        unsigned int i;
        int found = 0;
        for (i = 1; i <= pdb.p_types.nprim; i++) {
            if (ebitmap_get_bit(&pdb.permissive_map, i)) {
                printf("  *** PERMISSIVE: %s ***\n", type_name(&pdb, i));
                found++;
            }
        }
        if (!found) printf("  (none)\n");
    }

    /* === INTERESTING TYPES === */
    printf("\n======= 2. INTERESTING TYPES =======\n");
    unsigned int i;
    for (i = 1; i <= pdb.p_types.nprim; i++) {
        const char *n = type_name(&pdb, i);
        if (strstr(n, "su") || strstr(n, "root") || strstr(n, "rd_shell") ||
            strstr(n, "debug") || strstr(n, "permissive") || strstr(n, "unconfined") ||
            strstr(n, "recovery") || strstr(n, "engineer")) {
            type_datum_t *td = pdb.type_val_to_struct[i - 1];
            printf("  [%u] %s (flavor=%d)\n", i, n, td ? td->flavor : -1);
        }
    }

    /* === TYPE TRANSITIONS FROM shell === */
    printf("\n======= 3. TRANSITIONS FROM shell =======\n");
    dump_transitions_for(&pdb, "shell");

    printf("\n======= 4. TRANSITIONS FROM untrusted_app =======\n");
    dump_transitions_for(&pdb, "untrusted_app");

    /* === rd_shell_exec === */
    printf("\n======= 5a. ALLOW RULES TARGETING rd_shell_exec =======\n");
    dump_allow_for(&pdb, "rd_shell_exec"); /* Note: this dumps FROM, not TO */
    
    printf("\n======= 5b. TRANSITIONS TO rd_shell =======\n");
    dump_transitions_to(&pdb, "rd_shell");
    
    printf("\n======= 5c. ALLOW FROM rd_shell =======\n");
    dump_allow_for(&pdb, "rd_shell");

    printf("\n======= 6a. ALLOW TARGETING su_exec =======\n");
    dump_allow_for(&pdb, "su_exec");
    
    printf("\n======= 6b. TRANSITIONS TO su =======\n");
    dump_transitions_to(&pdb, "su");
    
    printf("\n======= 6c. ALLOW FROM su =======\n");
    dump_allow_for(&pdb, "su");

    /* === SHELL EXECUTE PERMISSIONS === */
    printf("\n======= 7. SHELL EXECUTE PERMS =======\n");
    {
        uint32_t src = find_type(&pdb, "shell");
        if (src) {
            avtab_t *a = &pdb.te_avtab;
            unsigned int i;
            for (i = 0; i < a->nslot; i++) {
                avtab_ptr_t cur;
                for (cur = a->htable[i]; cur; cur = cur->next) {
                    if (cur->key.source_type == src &&
                        cur->key.specified & AVTAB_ALLOWED) {
                        /* Check if execute perm is set */
                        uint32_t perms = cur->datum.data;
                        /* execute is usually perm bit 1 or depends on class */
                        char pbuf[64];
                        int bit;
                        int has_exec = 0;
                        for (bit = 0; bit < 32; bit++) {
                            if (perms & (1 << bit)) {
                                perm_name(&pdb, cur->key.target_class,
                                         bit + 1, pbuf, sizeof(pbuf));
                                if (strcmp(pbuf, "execute") == 0 ||
                                    strcmp(pbuf, "execute_no_trans") == 0) {
                                    has_exec = 1;
                                    break;
                                }
                            }
                        }
                        if (has_exec) {
                            printf("  allow shell %s:%s {",
                                   type_name(&pdb, cur->key.target_type),
                                   class_name(&pdb, cur->key.target_class));
                            dump_perms(&pdb, cur->key.target_class, perms);
                            printf(" };\n");
                        }
                    }
                }
            }
        }
    }

    /* === BLUETOOTH DOMAIN === */
    printf("\n======= 8. BLUETOOTH KEY PRIVILEGES =======\n");
    dump_allow_for(&pdb, "bluetooth");

    /* === DIAGEXE === */
    printf("\n======= 9. DIAGEXE ALL RULES =======\n");
    dump_allow_for(&pdb, "diagexe");

    /* === ENTRYPOINTS === */
    printf("\n======= 10. DOMAIN ENTRYPOINTS =======\n");
    {
        avtab_t *a = &pdb.te_avtab;
        unsigned int i;
        for (i = 0; i < a->nslot; i++) {
            avtab_ptr_t cur;
            for (cur = a->htable[i]; cur; cur = cur->next) {
                if (cur->key.specified & AVTAB_ALLOWED) {
                    uint32_t perms = cur->datum.data;
                    char pbuf[64];
                    int bit;
                    for (bit = 0; bit < 32; bit++) {
                        if (perms & (1 << bit)) {
                            perm_name(&pdb, cur->key.target_class,
                                     bit + 1, pbuf, sizeof(pbuf));
                            if (strcmp(pbuf, "entrypoint") == 0) {
                                printf("  %s <- %s\n",
                                       type_name(&pdb, cur->key.source_type),
                                       type_name(&pdb, cur->key.target_type));
                            }
                        }
                    }
                }
            }
        }
    }

    /* Dump all type names to file for Python analysis */
    {
        FILE *tf = fopen("/tmp/type_names.txt", "w");
        if (tf) {
            for (unsigned int i = 1; i <= pdb.p_types.nprim; i++) {
                const char *n = type_name(&pdb, i);
                type_datum_t *td = pdb.type_val_to_struct[i - 1];
                fprintf(tf, "%u\t%s\t%d\n", i, n, td ? td->flavor : -1);
            }
            fclose(tf);
            printf("Type names written to /tmp/type_names.txt\n");
        }
    }
    {
        FILE *cf = fopen("/tmp/class_names.txt", "w");
        if (cf) {
            for (unsigned int i = 1; i <= pdb.p_classes.nprim; i++) {
                const char *n = class_name(&pdb, i);
                fprintf(cf, "%u\t%s\n", i, n);
            }
            fclose(cf);
            printf("Class names written to /tmp/class_names.txt\n");
        }
    }

    policydb_destroy(&pdb);
    printf("\n======= ANALYSIS COMPLETE =======\n");
    return 0;
}
