/*
 * x86-64 指令长度解码 (仅长度, 不区分语义).
 *
 * 用途: baremetal 构建时在可执行段中定位真正的 syscall 指令
 * (opcode 0F 05)。直接字节扫描 0f 05 会误伤指令立即数/操作数中的
 * 相同字节序列 (例如 movabs $0x50f 的编码 48 b8 0f 05 ...), 导致
 * 切片行为被悄悄改变; 本解码器保证只把"完整解码为 2 字节 0F 05"
 * 的指令当作 syscall。
 *
 * 覆盖: 前缀 / REX / VEX / EVEX / XOP, 一字节表, 0F 表, 0F38/0F3A,
 * ModRM/SIB/disp/立即数。不覆盖 16 位代码段。
 */
#include "disasm.h"

/* ModRM 长度: mod!=3 且 rm==4 时含 SIB; 按 mod 加 disp */
static int modrm_len(const uint8_t *p, size_t cap)
{
    if (cap < 1)
        return -1;
    uint8_t m = p[0];
    int len = 1;
    if ((m & 0xC0) != 0xC0 && (m & 0x07) == 0x04) { /* SIB */
        if (cap < 2)
            return -1;
        uint8_t sib = p[1];
        len++;
        if ((m & 0xC0) == 0 && (sib & 0x07) == 0x05) {
            if (cap < 6)
                return -1;
            len += 4;           /* disp32 */
        }
    }
    switch (m >> 6) {
    case 0:
        if ((m & 0x07) == 0x05) {   /* [rip+disp32] */
            if (cap < 5)
                return -1;
            len += 4;
        }
        break;
    case 1:
        if (cap < 2)
            return -1;
        len += 1;               /* disp8 */
        break;
    case 2:
        if (cap < 5)
            return -1;
        len += 4;               /* disp32 */
        break;
    }
    return len;
}

static int opsize64(int has66, int rexw)
{
    if (rexw)
        return 2;               /* 64 位 */
    if (has66)
        return 0;               /* 16 位 */
    return 1;                   /* 32 位 */
}

/* 一字节表: 0=无 modrm, 1=modrm, -1=未知 */
static int t1(uint8_t op)
{
    switch (op) {
    case 0x00: case 0x01: case 0x02: case 0x03: /* add */
    case 0x08: case 0x09: case 0x0A: case 0x0B: /* or */
    case 0x10: case 0x11: case 0x12: case 0x13: /* adc */
    case 0x18: case 0x19: case 0x1A: case 0x1B: /* sbb */
    case 0x20: case 0x21: case 0x22: case 0x23: /* and */
    case 0x28: case 0x29: case 0x2A: case 0x2B: /* sub */
    case 0x30: case 0x31: case 0x32: case 0x33: /* xor */
    case 0x38: case 0x39: case 0x3A: case 0x3B: /* cmp */
    case 0x63: case 0x69: case 0x6B:
    case 0x80: case 0x81: case 0x82: case 0x83:
    case 0x84: case 0x85: case 0x86: case 0x87:
    case 0x88: case 0x89: case 0x8A: case 0x8B:
    case 0x8C: case 0x8D: case 0x8E: case 0x8F:
    case 0xC0: case 0xC1: case 0xC6: case 0xC7:
    case 0xD0: case 0xD1: case 0xD2: case 0xD3:
    case 0xD8: case 0xD9: case 0xDA: case 0xDB: case 0xDC:
    case 0xDD: case 0xDE: case 0xDF:
    case 0xF6: case 0xF7: case 0xFE: case 0xFF:
        return 1;
    case 0x04: case 0x05:       /* add AL/eAX imm */
    case 0x0C: case 0x0D:
    case 0x14: case 0x15:
    case 0x1C: case 0x1D:
    case 0x24: case 0x25:
    case 0x2C: case 0x2D:
    case 0x34: case 0x35:
    case 0x3C: case 0x3D:
    case 0x50: case 0x51: case 0x52: case 0x53: case 0x54: case 0x55:
    case 0x56: case 0x57: case 0x58: case 0x59: case 0x5A: case 0x5B:
    case 0x5C: case 0x5D: case 0x5E: case 0x5F: /* push/pop r64 */
    case 0x60: case 0x61:
    case 0x68: case 0x6A:
    case 0x6C: case 0x6D: case 0x6E: case 0x6F:
    case 0x70: case 0x71: case 0x72: case 0x73: case 0x74: case 0x75:
    case 0x76: case 0x77: case 0x78: case 0x79: case 0x7A: case 0x7B:
    case 0x7C: case 0x7D: case 0x7E: case 0x7F: /* jcc rel8 */
    case 0x90: case 0x91: case 0x92: case 0x93: case 0x94: case 0x95:
    case 0x96: case 0x97: case 0x98: case 0x99: case 0x9B:
    case 0x9C: case 0x9D: case 0x9E: case 0x9F:
    case 0xA0: case 0xA1: case 0xA2: case 0xA3: /* moffs */
    case 0xA4: case 0xA5: case 0xA6: case 0xA7:
    case 0xA8: case 0xA9:
    case 0xAA: case 0xAB: case 0xAC: case 0xAD:
    case 0xAE: case 0xAF:
    case 0xB0: case 0xB1: case 0xB2: case 0xB3: case 0xB4: case 0xB5:
    case 0xB6: case 0xB7:
    case 0xB8: case 0xB9: case 0xBA: case 0xBB: case 0xBC: case 0xBD:
    case 0xBE: case 0xBF:
    case 0xC2: case 0xC3: case 0xC8: case 0xC9:
    case 0xCA: case 0xCB: case 0xCC: case 0xCD: case 0xCE: case 0xCF:
    case 0xD4: case 0xD5: case 0xD6: case 0xD7:
    case 0xE0: case 0xE1: case 0xE2: case 0xE3: case 0xE4: case 0xE5:
    case 0xE6: case 0xE7: case 0xE8: case 0xE9: case 0xEA: case 0xEB:
    case 0xEC: case 0xED: case 0xEE: case 0xEF:
    case 0xF1: case 0xF4: case 0xF5:
    case 0xF8: case 0xF9: case 0xFA: case 0xFB:
    case 0xFC: case 0xFD:
        return 0;
    default:
        return -1;
    }
}

/* 0F 表: 0=无 modrm, 1=modrm, -1=未知 */
static int t0f(uint8_t op2)
{
    switch (op2) {
    case 0x05: case 0x06: case 0x07: case 0x08: case 0x09: case 0x0B:
    case 0x0E: case 0x30: case 0x31: case 0x32: case 0x33: case 0x34:
    case 0x35: case 0x37: case 0x77: case 0xA0: case 0xA1: case 0xA2:
    case 0xA8: case 0xA9: case 0xC8: case 0xC9: case 0xCA: case 0xCB:
    case 0xCC: case 0xCD: case 0xCE: case 0xCF:
    case 0x80: case 0x81: case 0x82: case 0x83: case 0x84: case 0x85:
    case 0x86: case 0x87: case 0x88: case 0x89: case 0x8A: case 0x8B:
    case 0x8C: case 0x8D: case 0x8E: case 0x8F: /* jcc rel32 */
        return 0;
    case 0x0D: case 0x0F: case 0x10: case 0x11: case 0x12: case 0x13:
    case 0x14: case 0x15: case 0x16: case 0x17: case 0x18: case 0x19:
    case 0x1A: case 0x1B: case 0x1C: case 0x1D: case 0x1E: case 0x1F:
    case 0x20: case 0x21: case 0x22: case 0x23:
    case 0x28: case 0x29: case 0x2A: case 0x2B: case 0x2C: case 0x2D:
    case 0x2E: case 0x2F:
    case 0x40: case 0x41: case 0x42: case 0x43: case 0x44: case 0x45:
    case 0x46: case 0x47: case 0x48: case 0x49: case 0x4A: case 0x4B:
    case 0x4C: case 0x4D: case 0x4E: case 0x4F:
    case 0x50: case 0x51: case 0x52: case 0x53: case 0x54: case 0x55:
    case 0x56: case 0x57: case 0x58: case 0x59: case 0x5A: case 0x5B:
    case 0x5C: case 0x5D: case 0x5E: case 0x5F:
    case 0x60: case 0x61: case 0x62: case 0x63: case 0x64: case 0x65:
    case 0x66: case 0x67: case 0x68: case 0x69: case 0x6A: case 0x6B:
    case 0x6C: case 0x6D: case 0x6E: case 0x6F:
    case 0x70: case 0x71: case 0x72: case 0x73: case 0x74: case 0x75:
    case 0x76:
    case 0x78: case 0x79: case 0x7A: case 0x7B: case 0x7C: case 0x7D:
    case 0x7E: case 0x7F:
    case 0x90: case 0x91: case 0x92: case 0x93: case 0x94: case 0x95:
    case 0x96: case 0x97: case 0x98: case 0x99: case 0x9A: case 0x9B:
    case 0x9C: case 0x9D: case 0x9E: case 0x9F:
    case 0xA3: case 0xA4: case 0xA5: case 0xAB: case 0xAC: case 0xAD:
    case 0xAE: case 0xAF:
    case 0xB0: case 0xB1: case 0xB2: case 0xB3: case 0xB4: case 0xB5:
    case 0xB6: case 0xB7: case 0xB8: case 0xB9: case 0xBB: case 0xBC:
    case 0xBD: case 0xBE: case 0xBF:
    case 0xC0: case 0xC1: case 0xC3: case 0xC7:
    case 0xD0: case 0xD1: case 0xD2: case 0xD3: case 0xD4: case 0xD5:
    case 0xD6: case 0xD7: case 0xD8: case 0xD9: case 0xDA: case 0xDB:
    case 0xDC: case 0xDD: case 0xDE: case 0xDF:
    case 0xE0: case 0xE1: case 0xE2: case 0xE3: case 0xE4: case 0xE5:
    case 0xE6: case 0xE7: case 0xE8: case 0xE9: case 0xEA: case 0xEB:
    case 0xEC: case 0xED: case 0xEE: case 0xEF:
    case 0xF0: case 0xF1: case 0xF2: case 0xF3: case 0xF4: case 0xF5:
    case 0xF6: case 0xF7: case 0xF8: case 0xF9: case 0xFA: case 0xFB:
    case 0xFC: case 0xFD: case 0xFE: case 0xFF:
        return 1;
    default:
        return -1;
    }
}

int x86_len(const uint8_t *p, size_t cap)
{
    int has66 = 0, has67 = 0, rexw = 0;
    size_t i = 0;
    for (;;) {
        if (i >= cap || i >= 15)
            return -1;
        uint8_t b = p[i];
        if (b == 0x66)
            has66 = 1;
        else if (b == 0x67)
            has67 = 1;
        else if (b == 0xF0 || b == 0xF2 || b == 0xF3 ||
                 b == 0x2E || b == 0x36 || b == 0x3E ||
                 b == 0x26 || b == 0x64 || b == 0x65)
            ;
        else if (b >= 0x40 && b <= 0x4F)
            rexw = (b & 8) != 0;
        else
            break;
        i++;
    }
    int vmap = 0;               /* 0=一字节表 1=0F 2=0F38 3=0F3A */
    if (i >= cap)
        return -1;
    if (p[i] == 0xC5) {         /* 2-byte VEX, 0F 表 */
        if (cap < i + 2)
            return -1;
        vmap = 1;
        i += 2;
    } else if (p[i] == 0xC4) {  /* 3-byte VEX */
        if (cap < i + 3)
            return -1;
        int mm = p[i + 1] & 0x1F;
        if (mm == 1)
            vmap = 1;
        else if (mm == 2)
            vmap = 2;
        else if (mm == 3)
            vmap = 3;
        else
            return -1;
        i += 3;
    } else if (p[i] == 0x62) {  /* EVEX */
        if (cap < i + 4)
            return -1;
        int mm = p[i + 1] & 0x03;
        if (mm == 1)
            vmap = 1;
        else if (mm == 2)
            vmap = 2;
        else if (mm == 3)
            vmap = 3;
        else
            return -1;
        i += 4;
    } else if (p[i] == 0x8F) {  /* XOP */
        if (cap < i + 3)
            return -1;
        int mm = p[i + 1] >> 5;
        if (mm == 8)
            vmap = 1;
        else if (mm == 9)
            vmap = 2;
        else if (mm == 10)
            vmap = 3;
        else
            return -1;
        i += 3;
    }
    if (i >= cap)
        return -1;
    uint8_t op = p[i++];
    int has_modrm = -1, imm = 0;

    if (vmap == 0) {
        if (op == 0x0F) {
            if (i >= cap)
                return -1;
            uint8_t op2 = p[i++];
            if (op2 == 0x38) {
                if (i >= cap)
                    return -1;
                (void)p[i++];
                has_modrm = 1;
            } else if (op2 == 0x3A) {
                if (i >= cap)
                    return -1;
                (void)p[i++];
                has_modrm = 1;
                imm = 1;
            } else {
                has_modrm = t0f(op2);
                if (has_modrm < 0)
                    return -1;
                if (op2 >= 0x80 && op2 <= 0x8F) {
                    has_modrm = 0;
                    imm = opsize64(has66, rexw) == 0 ? 2 : 4;
                } else if (op2 == 0x0F || op2 == 0xA4 || op2 == 0xAC ||
                           op2 == 0xBA || op2 == 0xC2 || op2 == 0xC4 ||
                           op2 == 0xC5 || op2 == 0xC6)
                    imm = 1;
            }
        } else {
            has_modrm = t1(op);
            if (has_modrm < 0)
                return -1;
            switch (op) {
            case 0x04: case 0x0C: case 0x14: case 0x1C:
            case 0x24: case 0x2C: case 0x34: case 0x3C:
            case 0xA8:
                imm = 1;
                break;
            case 0x05: case 0x0D: case 0x15: case 0x1D:
            case 0x25: case 0x2D: case 0x35: case 0x3D:
            case 0xA9:
                imm = opsize64(has66, rexw) == 0 ? 2 :
                      (opsize64(has66, rexw) == 2 ? 8 : 4);
                break;
            case 0x68: case 0x69:
                imm = opsize64(has66, rexw) == 0 ? 2 : 4;
                break;
            case 0x6A: case 0x6B:
                imm = 1;
                break;
            case 0xA0: case 0xA1: case 0xA2: case 0xA3:
                imm = has67 ? 4 : 8; /* moffs (地址大小) */
                break;
            case 0xB0: case 0xB1: case 0xB2: case 0xB3: case 0xB4:
            case 0xB5: case 0xB6: case 0xB7:
                imm = 1;
                break;
            case 0xB8: case 0xB9: case 0xBA: case 0xBB: case 0xBC:
            case 0xBD: case 0xBE: case 0xBF:
                imm = opsize64(has66, rexw) == 0 ? 2 :
                      (opsize64(has66, rexw) == 2 ? 8 : 4);
                break;
            case 0xC0: case 0xC1:
                imm = 1;
                break;
            case 0xC2: case 0xCA:
                imm = 2;
                break;
            case 0xC8:
                imm = 3;
                break;
            case 0xCD: case 0xD4: case 0xD5: case 0xE4: case 0xE5:
            case 0xE6: case 0xE7:
                imm = 1;
                break;
            case 0xE8: case 0xE9:
                imm = opsize64(has66, rexw) == 0 ? 2 : 4;
                break;
            case 0xEB: case 0xE0: case 0xE1: case 0xE2: case 0xE3:
            case 0x70: case 0x71: case 0x72: case 0x73: case 0x74:
            case 0x75: case 0x76: case 0x77: case 0x78: case 0x79:
            case 0x7A: case 0x7B: case 0x7C: case 0x7D: case 0x7E:
            case 0x7F:
                imm = 1;
                break;
            case 0x80: case 0x81: case 0x82: case 0x83:
                imm = (op == 0x83 || op == 0x82) ? 1 :
                      (opsize64(has66, rexw) == 0 ? 2 : 4);
                break;
            case 0xC6: case 0xC7:
                imm = (op == 0xC6) ? 1 :
                      (opsize64(has66, rexw) == 0 ? 2 : 4);
                break;
            case 0xF6: case 0xF7:
                /* 仅 /0 (TEST) 带立即数, 其他 /r 无 */
                if (i < cap && (p[i] >> 3 & 7) == 0)
                    imm = (op == 0xF6) ? 1 :
                          (opsize64(has66, rexw) == 0 ? 2 : 4);
                break;
            }
        }
    } else if (vmap == 1) {
        has_modrm = t0f(op);
        if (has_modrm < 0)
            return -1;
        if (op >= 0x80 && op <= 0x8F) {
            has_modrm = 0;
            imm = 4;
        } else if (op == 0x0F || op == 0xA4 || op == 0xAC || op == 0xBA ||
                   op == 0xC2 || op == 0xC4 || op == 0xC5 || op == 0xC6)
            imm = 1;
    } else {
        has_modrm = 1;
        if (vmap == 3)
            imm = 1;
    }

    if (has_modrm == 1) {
        int l = modrm_len(p + i, cap - i);
        if (l < 0)
            return -1;
        i += (size_t)l;
    }
    if (imm == 8) {
        if (cap - i < 8)
            return -1;
        i += 8;
    } else if (imm == 4) {
        if (cap - i < 4)
            return -1;
        i += 4;
    } else if (imm) {
        if (cap - i < (size_t)imm)
            return -1;
        i += (size_t)imm;
    }
    return (int)i;
}

int x86_is_syscall(const uint8_t *p, size_t cap)
{
    if (cap < 2)
        return 0;
    if (p[0] != 0x0F || p[1] != 0x05)
        return 0;
    return x86_len(p, cap) == 2;
}
