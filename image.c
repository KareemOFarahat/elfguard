#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "image.h"

/* ELF header field offsets. Identical for both classes up to e_version. */
#define EI_CLASS 4
#define EI_DATA  5
#define ELFCLASS32 1
#define ELFCLASS64 2
#define ELFDATA2LSB 1
#define ELFDATA2MSB 2

static bool add_ovf(uint64_t a, uint64_t b, uint64_t *out)
{
    if (a > UINT64_MAX - b) return true;
    *out = a + b;
    return false;
}

const void *img_at(const eg_image *img, uint64_t off, uint64_t size)
{
    uint64_t end;
    if (add_ovf(off, size, &end)) return NULL;   /* refuse wraparound */
    if (end > (uint64_t)img->len) return NULL;
    return img->base + off;
}

static uint16_t rd16(const uint8_t *p, bool le)
{
    return le ? (uint16_t)(p[0] | (p[1] << 8))
              : (uint16_t)(p[1] | (p[0] << 8));
}

static uint32_t rd32(const uint8_t *p, bool le)
{
    return le ? ((uint32_t)p[0] | ((uint32_t)p[1] << 8) |
                 ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24))
              : ((uint32_t)p[3] | ((uint32_t)p[2] << 8) |
                 ((uint32_t)p[1] << 16) | ((uint32_t)p[0] << 24));
}

static uint64_t rd64(const uint8_t *p, bool le)
{
    return le ? ((uint64_t)rd32(p, true) | ((uint64_t)rd32(p + 4, true) << 32))
              : ((uint64_t)rd32(p + 4, false) | ((uint64_t)rd32(p, false) << 32));
}

bool img_u16(const eg_image *img, uint64_t off, uint16_t *out)
{
    const uint8_t *p = img_at(img, off, 2);
    if (!p) return false;
    *out = rd16(p, img->little_endian);
    return true;
}

bool img_u32(const eg_image *img, uint64_t off, uint32_t *out)
{
    const uint8_t *p = img_at(img, off, 4);
    if (!p) return false;
    *out = rd32(p, img->little_endian);
    return true;
}

bool img_u64(const eg_image *img, uint64_t off, uint64_t *out)
{
    const uint8_t *p = img_at(img, off, 8);
    if (!p) return false;
    *out = rd64(p, img->little_endian);
    return true;
}

const char *img_str(const eg_image *img, uint64_t off)
{
    if (off >= (uint64_t)img->len) return NULL;
    const char *s = (const char *)img->base + off;
    /* memchr over the remaining bytes only — never walks past the mapping. */
    if (!memchr(s, '\0', img->len - (size_t)off)) return NULL;
    return s;
}

bool img_open(eg_image *img, const char *path, char *err, size_t errlen)
{
    memset(img, 0, sizeof(*img));
    img->fd = -1;

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        snprintf(err, errlen, "cannot open: %s", strerror(errno));
        return false;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        snprintf(err, errlen, "cannot stat: %s", strerror(errno));
        close(fd);
        return false;
    }
    if (!S_ISREG(st.st_mode)) {
        snprintf(err, errlen, "not a regular file");
        close(fd);
        return false;
    }
    if (st.st_size < 64) {
        snprintf(err, errlen, "too small to be an ELF file (%lld bytes)",
                 (long long)st.st_size);
        close(fd);
        return false;
    }

    void *m = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (m == MAP_FAILED) {
        snprintf(err, errlen, "mmap failed: %s", strerror(errno));
        close(fd);
        return false;
    }

    img->map  = m;
    img->base = (const uint8_t *)m;
    img->len  = (size_t)st.st_size;
    img->fd   = fd;
    return true;
}

void img_close(eg_image *img)
{
    if (img->map) munmap(img->map, img->len);
    if (img->fd >= 0) close(img->fd);
    img->base = NULL;
    img->map = NULL;
    img->fd = -1;
}

bool img_parse_ehdr(eg_image *img, char *err, size_t errlen)
{
    if (memcmp(img->base, "\x7f" "ELF", 4) != 0) {
        snprintf(err, errlen, "not an ELF file (bad magic)");
        return false;
    }

    switch (img->base[EI_CLASS]) {
    case ELFCLASS32: img->bits = 32; break;
    case ELFCLASS64: img->bits = 64; break;
    default:
        snprintf(err, errlen, "unknown ELF class %u", img->base[EI_CLASS]);
        return false;
    }

    switch (img->base[EI_DATA]) {
    case ELFDATA2LSB: img->little_endian = true;  break;
    case ELFDATA2MSB: img->little_endian = false; break;
    default:
        snprintf(err, errlen, "unknown ELF data encoding %u", img->base[EI_DATA]);
        return false;
    }

    const bool is64 = (img->bits == 64);
    uint32_t tmp32;

    if (!img_u16(img, 16, &img->e_type) ||
        !img_u16(img, 18, &img->e_machine)) {
        snprintf(err, errlen, "truncated ELF header");
        return false;
    }

    if (is64) {
        if (!img_u64(img, 32, &img->e_phoff) ||
            !img_u64(img, 40, &img->e_shoff) ||
            !img_u16(img, 54, &img->e_phentsize) ||
            !img_u16(img, 56, &img->e_phnum) ||
            !img_u16(img, 58, &img->e_shentsize) ||
            !img_u16(img, 60, &img->e_shnum) ||
            !img_u16(img, 62, &img->e_shstrndx)) {
            snprintf(err, errlen, "truncated ELF64 header");
            return false;
        }
    } else {
        if (!img_u32(img, 28, &tmp32)) goto trunc32;
        img->e_phoff = tmp32;
        if (!img_u32(img, 32, &tmp32)) goto trunc32;
        img->e_shoff = tmp32;
        if (!img_u16(img, 42, &img->e_phentsize) ||
            !img_u16(img, 44, &img->e_phnum) ||
            !img_u16(img, 46, &img->e_shentsize) ||
            !img_u16(img, 48, &img->e_shnum) ||
            !img_u16(img, 50, &img->e_shstrndx)) goto trunc32;
    }

    /* A header that lies about its own entry size will desync the whole table
     * walk, so reject it rather than reading at attacker-chosen strides. */
    const uint16_t want_ph = is64 ? 56 : 32;
    const uint16_t want_sh = is64 ? 64 : 40;
    if (img->e_phnum && img->e_phentsize != want_ph) {
        snprintf(err, errlen, "implausible e_phentsize %u (expected %u)",
                 img->e_phentsize, want_ph);
        return false;
    }
    if (img->e_shnum && img->e_shentsize != want_sh) {
        snprintf(err, errlen, "implausible e_shentsize %u (expected %u)",
                 img->e_shentsize, want_sh);
        return false;
    }
    return true;

trunc32:
    snprintf(err, errlen, "truncated ELF32 header");
    return false;
}

bool img_phdr(const eg_image *img, uint16_t i, eg_phdr *out)
{
    if (i >= img->e_phnum) return false;
    const uint64_t off = img->e_phoff + (uint64_t)i * img->e_phentsize;
    if (!img_at(img, off, img->e_phentsize)) return false;

    memset(out, 0, sizeof(*out));
    if (img->bits == 64) {
        uint32_t t, f; uint64_t o, v, fs, ms;
        if (!img_u32(img, off + 0,  &t)  || !img_u32(img, off + 4,  &f)  ||
            !img_u64(img, off + 8,  &o)  || !img_u64(img, off + 16, &v)  ||
            !img_u64(img, off + 32, &fs) || !img_u64(img, off + 40, &ms))
            return false;
        out->type = t; out->flags = f; out->offset = o;
        out->vaddr = v; out->filesz = fs; out->memsz = ms;
    } else {
        uint32_t t, o, v, fs, ms, f;
        if (!img_u32(img, off + 0,  &t)  || !img_u32(img, off + 4,  &o)  ||
            !img_u32(img, off + 8,  &v)  || !img_u32(img, off + 16, &fs) ||
            !img_u32(img, off + 20, &ms) || !img_u32(img, off + 24, &f))
            return false;
        out->type = t; out->flags = f; out->offset = o;
        out->vaddr = v; out->filesz = fs; out->memsz = ms;
    }
    return true;
}

bool img_shdr(const eg_image *img, uint16_t i, eg_shdr *out)
{
    if (i >= img->e_shnum) return false;
    const uint64_t off = img->e_shoff + (uint64_t)i * img->e_shentsize;
    if (!img_at(img, off, img->e_shentsize)) return false;

    memset(out, 0, sizeof(*out));
    if (img->bits == 64) {
        uint32_t n, t, l, inf; uint64_t fl, ad, o, sz, es;
        if (!img_u32(img, off + 0,  &n)  || !img_u32(img, off + 4,  &t)  ||
            !img_u64(img, off + 8,  &fl) || !img_u64(img, off + 16, &ad) ||
            !img_u64(img, off + 24, &o)  || !img_u64(img, off + 32, &sz) ||
            !img_u32(img, off + 40, &l)  || !img_u32(img, off + 44, &inf) ||
            !img_u64(img, off + 56, &es))
            return false;
        out->name = n; out->type = t; out->flags = fl; out->addr = ad;
        out->offset = o; out->size = sz; out->link = l; out->info = inf;
        out->entsize = es;
    } else {
        uint32_t n, t, fl, ad, o, sz, l, inf, es;
        if (!img_u32(img, off + 0,  &n)  || !img_u32(img, off + 4,  &t)  ||
            !img_u32(img, off + 8,  &fl) || !img_u32(img, off + 12, &ad) ||
            !img_u32(img, off + 16, &o)  || !img_u32(img, off + 20, &sz) ||
            !img_u32(img, off + 24, &l)  || !img_u32(img, off + 28, &inf) ||
            !img_u32(img, off + 36, &es))
            return false;
        out->name = n; out->type = t; out->flags = fl; out->addr = ad;
        out->offset = o; out->size = sz; out->link = l; out->info = inf;
        out->entsize = es;
    }
    return true;
}
