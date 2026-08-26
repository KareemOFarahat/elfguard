/* image.h — bounds-checked, read-only view over an on-disk file.
 *
 * THREAT MODEL: the input file is hostile. It may be truncated, it may claim a
 * section header table that starts past EOF, it may declare 65535 program
 * headers in a 40-byte file, it may point a string table offset at a wildcard
 * address. A parser that trusts any of those numbers is itself a bug.
 *
 * So: nothing in this codebase dereferences a file-derived offset directly.
 * Every read goes through img_at(), which validates offset + size against the
 * real mapped length *using arithmetic that cannot overflow*.
 */
#ifndef ELFGUARD_IMAGE_H
#define ELFGUARD_IMAGE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "elfguard.h"

typedef struct {
    const uint8_t *base;   /* read-only alias of `map`, used by all readers */
    void          *map;    /* the mapping itself, kept non-const for munmap */
    size_t         len;
    int            fd;

    /* parsed once, reused by every check */
    bool     little_endian;
    int      bits;
    uint16_t e_type;
    uint16_t e_machine;
    uint64_t e_phoff, e_shoff;
    uint16_t e_phnum, e_shnum, e_phentsize, e_shentsize, e_shstrndx;
} eg_image;

/* Map `path`. Returns false and fills `err` on failure. */
bool img_open(eg_image *img, const char *path, char *err, size_t errlen);
void img_close(eg_image *img);

/* The only sanctioned way to touch file bytes.
 * Returns NULL if [off, off+size) is not entirely inside the mapping. */
const void *img_at(const eg_image *img, uint64_t off, uint64_t size);

/* Endian-correct scalar reads. Return false if out of bounds. */
bool img_u16(const eg_image *img, uint64_t off, uint16_t *out);
bool img_u32(const eg_image *img, uint64_t off, uint32_t *out);
bool img_u64(const eg_image *img, uint64_t off, uint64_t *out);

/* Read a NUL-terminated string at `off`, refusing to run off the end of the
 * mapping. Returns NULL if unterminated within the file. */
const char *img_str(const eg_image *img, uint64_t off);

/* Validate the ELF identity and header. Fills the e_* fields. */
bool img_parse_ehdr(eg_image *img, char *err, size_t errlen);

/* Iterate headers. Return false when `i` is out of range or malformed. */
bool img_phdr(const eg_image *img, uint16_t i, eg_phdr *out);
bool img_shdr(const eg_image *img, uint16_t i, eg_shdr *out);

#endif /* ELFGUARD_IMAGE_H */
