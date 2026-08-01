/*
 * DWARF 地址偏置修补
 *
 * PIE 程序的 .debug_* 节中地址是 0 基 (镜像相对) 的, 而切片 ELF 恢复进程
 * 到随机化基址, 地址需要加 exe_bias 才能与运行时一致。
 *
 * 本模块扫描 DWARF v4/v5 的 .debug_info / .debug_line / .debug_aranges /
 * .debug_ranges / .debug_rnglists / .debug_addr 节, 对所有地址形式字段
 * 加 bias。.debug_loc/.debug_loclists 暂不处理 (v1 限制)。
 */
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "util.h"

#define DW_FORM_addr      0x01
#define DW_FORM_block2    0x03
#define DW_FORM_block4    0x04
#define DW_FORM_data2     0x05
#define DW_FORM_data4     0x06
#define DW_FORM_data8     0x07
#define DW_FORM_string    0x08
#define DW_FORM_block     0x09
#define DW_FORM_block1    0x0a
#define DW_FORM_data1     0x0b
#define DW_FORM_flag      0x0c
#define DW_FORM_sdata     0x0d
#define DW_FORM_strp      0x0e
#define DW_FORM_udata     0x0f
#define DW_FORM_ref_addr  0x10
#define DW_FORM_ref1      0x11
#define DW_FORM_ref2      0x12
#define DW_FORM_ref4      0x13
#define DW_FORM_ref8      0x14
#define DW_FORM_ref_udata 0x15
#define DW_FORM_indirect  0x16
#define DW_FORM_sec_offset 0x17
#define DW_FORM_exprloc   0x18
#define DW_FORM_flag_present 0x19
#define DW_FORM_strx      0x1a
#define DW_FORM_addrx     0x1b
#define DW_FORM_ref_sup   0x1c
#define DW_FORM_strp_sup  0x1d
#define DW_FORM_data16    0x1e
#define DW_FORM_line_strp 0x1f
#define DW_FORM_ref_sig8  0x20
#define DW_FORM_implicit_const 0x21
#define DW_FORM_loclistx  0x22
#define DW_FORM_rnglistx  0x23
#define DW_FORM_ref_sup8  0x24
#define DW_FORM_strx1     0x25
#define DW_FORM_strx2     0x26
#define DW_FORM_strx3     0x27
#define DW_FORM_strx4     0x28
#define DW_FORM_addrx1    0x29
#define DW_FORM_addrx2    0x2a
#define DW_FORM_addrx3    0x2b
#define DW_FORM_addrx4    0x2c

#define DW_RLE_end_of_list 0x00
#define DW_RLE_base_addressx 0x01
#define DW_RLE_startx_endx 0x02
#define DW_RLE_startx_length 0x03
#define DW_RLE_offset_pair 0x04
#define DW_RLE_base_address 0x05
#define DW_RLE_start_end   0x06
#define DW_RLE_start_length 0x07

#define DW_FORM_implicit_const 0x21

struct dwarf_patch {
    const uint8_t *abbrev;      /* .debug_abbrev 节 */
    size_t abbrev_size;
    uint64_t bias;
};

static uint64_t rd_uleb(const uint8_t **pp, const uint8_t *end)
{
    uint64_t v = 0;
    int shift = 0;
    const uint8_t *p = *pp;
    while (p < end && shift < 64) {
        uint8_t b = *p++;
        v |= (uint64_t)(b & 0x7f) << shift;
        if (!(b & 0x80))
            break;
        shift += 7;
    }
    *pp = p;
    return v;
}

static int64_t rd_sleb(const uint8_t **pp, const uint8_t *end)
{
    int64_t v = 0;
    int shift = 0;
    uint8_t b;
    const uint8_t *p = *pp;
    do {
        if (p >= end || shift >= 64)
            break;
        b = *p++;
        v |= (int64_t)(b & 0x7f) << shift;
        shift += 7;
    } while (b & 0x80);
    if (shift < 64 && (b & 0x40))
        v |= -(1LL << shift);
    *pp = p;
    return v;
}

static uint64_t rd_unit_len(const uint8_t *data, size_t size, size_t off,
                            uint64_t *hdr, uint64_t *unit_len)
{
    if (off + 4 > size)
        return 0;
    uint64_t l = data[off] | (data[off+1] << 8) | (data[off+2] << 16) |
                 ((uint32_t)data[off+3] << 24);
    if (l == 0xffffffff) {
        if (off + 12 > size)
            return 0;
        l = 0;
        for (int i = 0; i < 8; i++)
            l |= (uint64_t)data[off + 4 + i] << (8 * i);
        *hdr = 12;
    } else {
        *hdr = 4;
    }
    *unit_len = l;
    return l ? off + 4 + l : 0;
}

/* 对 address 加 bias */
static void add_bias(uint8_t *p, int asize, uint64_t bias)
{
    for (int i = 0; i < asize; i++)
        p[i] += (bias >> (8 * i)) & 0xff;
}

/* 按 form 跳过 DIE 流中的属性值, 返回 0 = 成功 */
static int skip_form(const uint8_t **pp, const uint8_t *end, uint64_t form,
                     int asize, int version, int dwarf64)
{
    int sz4 = dwarf64 ? 8 : 4;      /* DWARF32/64 引用字段大小 */
    const uint8_t *p = *pp;
    uint64_t n;

    switch (form) {
    case DW_FORM_addr:
        p += asize;
        break;
    case DW_FORM_addrx:
    case DW_FORM_udata:
    case DW_FORM_sdata:
    case DW_FORM_ref_udata:
    case DW_FORM_strx1: case DW_FORM_strx2:
    case DW_FORM_strx3: case DW_FORM_strx4:
    case DW_FORM_loclistx:
    case DW_FORM_rnglistx:
        rd_uleb(&p, end);
        break;
    case DW_FORM_addrx1: case DW_FORM_data1: case DW_FORM_flag:
    case DW_FORM_ref1:
        p += 1;
        break;
    case DW_FORM_addrx2: case DW_FORM_data2: case DW_FORM_ref2:
        p += 2;
        break;
    case DW_FORM_addrx3:
        p += 3;
        break;
    case DW_FORM_addrx4: case DW_FORM_data4: case DW_FORM_ref4:
    case DW_FORM_strp: case DW_FORM_strx: case DW_FORM_sec_offset:
    case DW_FORM_strp_sup: case DW_FORM_line_strp:
        p += sz4;
        break;
    case DW_FORM_data8: case DW_FORM_ref8: case DW_FORM_ref_sig8:
        p += 8;
        break;
    case DW_FORM_ref_addr:
        p += (version >= 5) ? sz4 : asize;
        break;
    case DW_FORM_data16:
        p += 16;
        break;
    case DW_FORM_string:
        while (p < end && *p)
            p++;
        p++;
        break;
    case DW_FORM_block1:
        if (p >= end) return -1;
        n = *p++;
        p += n;
        break;
    case DW_FORM_block2:
        if (p + 2 > end) return -1;
        n = p[0] | (p[1] << 8);
        p += 2 + n;
        break;
    case DW_FORM_block4:
        if (p + 4 > end) return -1;
        n = (uint32_t)p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24);
        p += 4 + n;
        break;
    case DW_FORM_block:
    case DW_FORM_exprloc:
        n = rd_uleb(&p, end);
        p += n;
        break;
    case DW_FORM_flag_present:
    case DW_FORM_ref_sup:
        break;
    case DW_FORM_implicit_const:
        /* 值在 abbrev 中, 不在流中 */
        break;
    default:
        return -1;
    }
    if (p > end)
        return -1;
    *pp = p;
    return 0;
}

/* 解析一个 CU 的 DIE 流, 对 DW_FORM_addr 加 bias */
static void patch_cu_dies(struct dwarf_patch *dp, const uint8_t *cu,
                          const uint8_t *cu_end, uint64_t abbrev_off,
                          int asize, int version, int dwarf64)
{
    const uint8_t *ab = dp->abbrev + abbrev_off;
    const uint8_t *ab_end = dp->abbrev + dp->abbrev_size;
    const uint8_t *p = cu;
    int depth = 0;

    if (abbrev_off >= dp->abbrev_size)
        return;

    while (p < cu_end) {
        uint64_t code = rd_uleb(&p, cu_end);
        if (code == 0) {
            if (depth == 0)
                return;         /* CU 结束 */
            depth--;
            continue;           /* 子 DIE 列表结束 */
        }
        /* 在 abbrev 表中定位该 code (一次扫描, 记录属性起始位置) */
        const uint8_t *q = ab;
        const uint8_t *attrs = NULL;
        uint64_t child = 0;
        while (q < ab_end) {
            uint64_t c = rd_uleb(&q, ab_end);
            if (c == 0)
                break;
            rd_uleb(&q, ab_end);            /* tag */
            child = rd_uleb(&q, ab_end);    /* has_children */
            if (c == code) {
                attrs = q;
                break;
            }
            for (;;) {                      /* 跳过属性对 */
                uint64_t name = rd_uleb(&q, ab_end);
                uint64_t form = rd_uleb(&q, ab_end);
                if (form == DW_FORM_implicit_const)
                    rd_sleb(&q, ab_end);    /* 值在 abbrev 中 */
                if (name == 0 && form == 0)
                    break;
            }
        }
        if (!attrs) {
            warn("dwarf: abbrev code %llu not found (depth %d), "
                 "remaining addresses in this CU left unpatched",
                 (unsigned long long)code, depth);
            return;
        }
        /* 属性值 */
        q = attrs;
        for (;;) {
            uint64_t name = rd_uleb(&q, ab_end);
            uint64_t form = rd_uleb(&q, ab_end);
            if (name == 0 && form == 0)
                break;
            if (form == DW_FORM_implicit_const) {
                rd_sleb(&q, ab_end);
                continue;
            }
            if (form == DW_FORM_addr) {
                add_bias((uint8_t *)p, asize, dp->bias);
                p += asize;
            } else {
                if (skip_form(&p, cu_end, form, asize, version, dwarf64) < 0)
                    return;
            }
        }
        if (child)
            depth++;
    }
}

static void patch_debug_info(struct dwarf_patch *dp, uint8_t *data, size_t size)
{
    size_t off = 0;

    while (off < size) {
        uint64_t hdr, unit_len, next, abbrev_off;
        uint16_t version;
        uint8_t asize;
        int dwarf64;
        const uint8_t *p;

        next = rd_unit_len(data, size, off, &hdr, &unit_len);
        if (!next)
            break;
        version = data[off + hdr] | (data[off + hdr + 1] << 8);
        dwarf64 = (hdr == 12);
        p = data + off + hdr + 2;
        if (version >= 5) {
            asize = p[1];       /* version(2) 后: unit_type(1), addr_size(1) */
            p += 2;
            if (hdr == 4) {
                abbrev_off = p[0] | (p[1] << 8) | (p[2] << 16) |
                             ((uint32_t)p[3] << 24);
                p += 4;
            } else {
                abbrev_off = 0;
                for (int i = 0; i < 8; i++)
                    abbrev_off |= (uint64_t)p[i] << (8 * i);
                p += 8;
            }
        } else {
            asize = 8;
            if (hdr == 4) {
                abbrev_off = p[0] | (p[1] << 8) | (p[2] << 16) |
                             ((uint32_t)p[3] << 24);
                p += 4;
            } else {
                abbrev_off = 0;
                for (int i = 0; i < 8; i++)
                    abbrev_off |= (uint64_t)p[i] << (8 * i);
                p += 8;
            }
            p += 1;             /* addr_size */
        }
        patch_cu_dies(dp, p, data + next, abbrev_off, asize, version,
                      dwarf64);
        off = next;
    }
}

/* .debug_line: 行程序, 对 DW_LNE_set_address 加 bias (v4/v5) */
static void patch_debug_line(struct dwarf_patch *dp, uint8_t *data, size_t size)
{
    size_t off = 0;

    while (off < size) {
        uint64_t hdr, unit_len, next;
        uint16_t version;
        uint8_t asize = 8, opcode_base;
        const uint8_t *p, *end;
        const uint8_t *opcode_lens;

        next = rd_unit_len(data, size, off, &hdr, &unit_len);
        if (!next)
            break;
        version = data[off + hdr] | (data[off + hdr + 1] << 8);
        p = data + off + hdr + 2;
        if (version >= 5) {
            asize = p[0];
            p += 2;             /* addr_size, segment_selector */
        }
        p += 4;                 /* header_length */
        end = data + next;
        if (end > data + size)
            end = data + size;
        /* min_inst, max_ops, line_base, line_range */
        p += 4;
        if (p >= end)
            break;
        opcode_base = *p++;
        opcode_lens = p;
        p += opcode_base - 1;
        if (version >= 5) {
            /* 目录表: format_count, (content_type, form) x n, count, entries */
            uint64_t nf = rd_uleb(&p, end);
            uint64_t forms[16];
            if (nf > 16) { p = end; }
            else {
                for (uint64_t j = 0; j < nf; j++) {
                    rd_uleb(&p, end);
                    forms[j] = rd_uleb(&p, end);
                }
                uint64_t count = rd_uleb(&p, end);
                for (uint64_t i = 0; i < count && p < end; i++)
                    for (uint64_t j = 0; j < nf && p < end; j++)
                        skip_form(&p, end, forms[j], asize, version, 0);
            }
            /* 文件表: 同上 */
            nf = rd_uleb(&p, end);
            if (nf > 16) { p = end; }
            else {
                for (uint64_t j = 0; j < nf; j++) {
                    rd_uleb(&p, end);
                    forms[j] = rd_uleb(&p, end);
                }
                uint64_t count = rd_uleb(&p, end);
                for (uint64_t i = 0; i < count && p < end; i++)
                    for (uint64_t j = 0; j < nf && p < end; j++)
                        skip_form(&p, end, forms[j], asize, version, 0);
            }
        } else {
            while (p < end && *p)
                p++;
            p++;
            while (p < end && *p) {
                p += strlen((const char *)p) + 1;
                rd_uleb(&p, end);
                rd_uleb(&p, end);
                rd_uleb(&p, end);
            }
            p++;
        }
        /* 行程序 */
        while (p < end) {
            uint8_t op = *p++;
            if (op == 0) {      /* extended */
                uint64_t len = rd_uleb(&p, end);
                const uint8_t *sub_end = p + len;
                if (sub_end > end)
                    sub_end = end;
                if (p < sub_end) {
                    uint8_t sub = *p++;
                    if (sub == 0x02)    /* DW_LNE_set_address */
                        add_bias((uint8_t *)p, asize, dp->bias);
                }
                p = sub_end;
            } else if (op < opcode_base) {
                uint8_t n = opcode_lens[op - 1];
                for (uint8_t i = 0; i < n && p < end; i++)
                    rd_uleb(&p, end);
            }
        }
        off = next;
    }
}

/* .debug_aranges: 头 + (address, length) 元组表 */
static void patch_debug_aranges(struct dwarf_patch *dp, uint8_t *data,
                                size_t size)
{
    size_t off = 0;

    while (off < size) {
        uint64_t hdr, unit_len, next;
        uint8_t asize, offsize;

        next = rd_unit_len(data, size, off, &hdr, &unit_len);
        if (!next)
            break;
        offsize = (hdr == 4) ? 4 : 8;
        asize = data[off + hdr + 2 + offsize];
        /* 元组区: 对齐到 2*asize */
        uint64_t tuple = (off + hdr + 2 + offsize + 2 + 2 * asize - 1) &
                         ~(uint64_t)(2 * asize - 1);
        while (tuple + 2 * asize <= next) {
            uint64_t a = 0, l = 0;
            for (int i = 0; i < asize; i++) {
                a |= (uint64_t)data[tuple + i] << (8 * i);
                l |= (uint64_t)data[tuple + asize + i] << (8 * i);
            }
            if (a == 0 && l == 0)
                break;
            add_bias(data + tuple, asize, dp->bias);
            tuple += 2 * asize;
        }
        off = next;
    }
}

/* .debug_ranges: (begin, end) 序列, (0,0) 终止符不动 */
static void patch_debug_ranges(struct dwarf_patch *dp, uint8_t *data,
                               size_t size)
{
    size_t p = 0;

    while (p + 16 <= size) {
        uint64_t a = 0, b = 0;
        for (int i = 0; i < 8; i++) {
            a |= (uint64_t)data[p + i] << (8 * i);
            b |= (uint64_t)data[p + 8 + i] << (8 * i);
        }
        if (!(a == 0 && b == 0)) {
            add_bias(data + p, 8, dp->bias);
            add_bias(data + p + 8, 8, dp->bias);
        }
        p += 16;
    }
}

/* .debug_rnglists (v5): 逐列表打补丁 */
static void patch_debug_rnglists(struct dwarf_patch *dp, uint8_t *data,
                                 size_t size)
{
    size_t off = 0;

    while (off < size) {
        uint64_t hdr, unit_len, next;
        uint8_t asize;
        const uint8_t *p, *end;

        next = rd_unit_len(data, size, off, &hdr, &unit_len);
        if (!next)
            break;
        asize = data[off + hdr + 2];
        p = data + off + hdr + 4;   /* version(2) + asize(1) + seg(1) */
        end = data + next;
        if (end > data + size)
            end = data + size;
        p += 4;                 /* offset_entry_count */
        for (;;) {
            uint8_t op;
            if (p >= end)
                break;
            op = *p++;
            switch (op) {
            case DW_RLE_end_of_list:
                break;
            case DW_RLE_base_addressx:
            case DW_RLE_startx_endx:
                rd_uleb(&p, end);
                if (op == DW_RLE_startx_endx)
                    rd_uleb(&p, end);
                break;
            case DW_RLE_startx_length:
                rd_uleb(&p, end);
                rd_uleb(&p, end);
                break;
            case DW_RLE_offset_pair:
                rd_uleb(&p, end);
                rd_uleb(&p, end);
                break;
            case DW_RLE_base_address:
                add_bias((uint8_t *)p, asize, dp->bias);
                p += asize;
                break;
            case DW_RLE_start_end:
                add_bias((uint8_t *)p, asize, dp->bias);
                p += asize;
                add_bias((uint8_t *)p, asize, dp->bias);
                p += asize;
                break;
            case DW_RLE_start_length:
                add_bias((uint8_t *)p, asize, dp->bias);
                p += asize;
                rd_uleb(&p, end);
                break;
            default:
                return;
            }
            if (op == DW_RLE_end_of_list)
                break;
        }
        off = next;
    }
}

/*
 * 对单个 .debug_* 节打 bias 补丁。
 * bias == 0 (非 PIE) 时不做任何事。
 */
int dwarf_patch_bias(uint8_t *data, size_t size, const char *name,
                     uint64_t bias, const uint8_t *abbrev, size_t abbrev_size)
{
    struct dwarf_patch dp = {0};

    if (bias == 0 || !data || size == 0)
        return 0;
    dp.bias = bias;
    dp.abbrev = abbrev;
    dp.abbrev_size = abbrev_size;

    if (strcmp(name, ".debug_info") == 0)
        patch_debug_info(&dp, data, size);
    else if (strcmp(name, ".debug_line") == 0)
        patch_debug_line(&dp, data, size);
    else if (strcmp(name, ".debug_aranges") == 0)
        patch_debug_aranges(&dp, data, size);
    else if (strcmp(name, ".debug_ranges") == 0)
        patch_debug_ranges(&dp, data, size);
    else if (strcmp(name, ".debug_rnglists") == 0)
        patch_debug_rnglists(&dp, data, size);
    return 0;
}
