#pragma once
const unsigned char injectWow64toNative64[] = {
    0x48, 0x89, 0x4c, 0x24, 0x08, 0x48, 0x81, 0xec, 0xb8, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x0d, 0x01, 
    0x40, 0x00, 0x00, 0xe8, 0x98, 0x03, 0x00, 0x00, 0x48, 0xc7, 0x84, 0x24, 0x88, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 
    0x24, 0x58, 0x48, 0x8b, 0x44, 0x24, 0x58, 0x48, 0x8b, 0x40, 0x18, 0x48, 0x89, 0x44, 0x24, 0x58, 
    0x48, 0x8b, 0x44, 0x24, 0x58, 0x48, 0x8b, 0x40, 0x20, 0x48, 0x89, 0x44, 0x24, 0x68, 0x48, 0x83, 
    0x7c, 0x24, 0x68, 0x00, 0x0f, 0x84, 0x20, 0x02, 0x00, 0x00, 0x48, 0x8b, 0x44, 0x24, 0x68, 0x48, 
    0x8b, 0x40, 0x50, 0x48, 0x89, 0x44, 0x24, 0x70, 0x48, 0x8b, 0x44, 0x24, 0x68, 0x0f, 0xb7, 0x40, 
    0x48, 0x66, 0x89, 0x44, 0x24, 0x50, 0x48, 0xc7, 0x44, 0x24, 0x60, 0x00, 0x00, 0x00, 0x00, 0x8b, 
    0x4c, 0x24, 0x60, 0xe8, 0xf8, 0x02, 0x00, 0x00, 0x8b, 0xc0, 0x48, 0x89, 0x44, 0x24, 0x60, 0x48, 
    0x8b, 0x44, 0x24, 0x70, 0x0f, 0xb6, 0x00, 0x83, 0xf8, 0x61, 0x7c, 0x1f, 0x48, 0x8b, 0x44, 0x24, 
    0x70, 0x0f, 0xb6, 0x00, 0x83, 0xe8, 0x20, 0x48, 0x98, 0x48, 0x8b, 0x4c, 0x24, 0x60, 0x48, 0x03, 
    0xc8, 0x48, 0x8b, 0xc1, 0x48, 0x89, 0x44, 0x24, 0x60, 0xeb, 0x18, 0x48, 0x8b, 0x44, 0x24, 0x70, 
    0x0f, 0xb6, 0x00, 0x48, 0x8b, 0x4c, 0x24, 0x60, 0x48, 0x03, 0xc8, 0x48, 0x8b, 0xc1, 0x48, 0x89, 
    0x44, 0x24, 0x60, 0x48, 0x8b, 0x44, 0x24, 0x70, 0x48, 0xff, 0xc0, 0x48, 0x89, 0x44, 0x24, 0x70, 
    0x0f, 0xb7, 0x44, 0x24, 0x50, 0x66, 0xff, 0xc8, 0x66, 0x89, 0x44, 0x24, 0x50, 0x0f, 0xb7, 0x44, 
    0x24, 0x50, 0x85, 0xc0, 0x75, 0x89, 0x81, 0x7c, 0x24, 0x60, 0x5d, 0x68, 0xfa, 0x3c, 0x0f, 0x85, 
    0x57, 0x01, 0x00, 0x00, 0x48, 0x8b, 0x44, 0x24, 0x68, 0x48, 0x8b, 0x40, 0x20, 0x48, 0x89, 0x44, 
    0x24, 0x58, 0x48, 0x8b, 0x44, 0x24, 0x58, 0x48, 0x63, 0x40, 0x3c, 0x48, 0x8b, 0x4c, 0x24, 0x58, 
    0x48, 0x03, 0xc8, 0x48, 0x8b, 0xc1, 0x48, 0x89, 0x44, 0x24, 0x78, 0xb8, 0x08, 0x00, 0x00, 0x00, 
    0x48, 0x6b, 0xc0, 0x00, 0x48, 0x8b, 0x4c, 0x24, 0x78, 0x48, 0x8d, 0x84, 0x01, 0x88, 0x00, 0x00, 
    0x00, 0x48, 0x89, 0x84, 0x24, 0x80, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x84, 0x24, 0x80, 0x00, 0x00, 
    0x00, 0x8b, 0x00, 0x48, 0x8b, 0x4c, 0x24, 0x58, 0x48, 0x03, 0xc8, 0x48, 0x8b, 0xc1, 0x48, 0x89, 
    0x44, 0x24, 0x78, 0x48, 0x8b, 0x44, 0x24, 0x78, 0x8b, 0x40, 0x20, 0x48, 0x8b, 0x4c, 0x24, 0x58, 
    0x48, 0x03, 0xc8, 0x48, 0x8b, 0xc1, 0x48, 0x89, 0x84, 0x24, 0x80, 0x00, 0x00, 0x00, 0x48, 0x8b, 
    0x44, 0x24, 0x78, 0x8b, 0x40, 0x24, 0x48, 0x8b, 0x4c, 0x24, 0x58, 0x48, 0x03, 0xc8, 0x48, 0x8b, 
    0xc1, 0x48, 0x89, 0x84, 0x24, 0xa0, 0x00, 0x00, 0x00, 0x33, 0xc0, 0x83, 0xf8, 0x01, 0x0f, 0x84, 
    0xb7, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x84, 0x24, 0x80, 0x00, 0x00, 0x00, 0x8b, 0x00, 0x48, 0x8b, 
    0x4c, 0x24, 0x58, 0x48, 0x03, 0xc8, 0x48, 0x8b, 0xc1, 0x48, 0x8b, 0xc8, 0xe8, 0x3f, 0x01, 0x00, 
    0x00, 0x89, 0x84, 0x24, 0x90, 0x00, 0x00, 0x00, 0x81, 0xbc, 0x24, 0x90, 0x00, 0x00, 0x00, 0x41, 
    0x20, 0x2f, 0x44, 0x75, 0x59, 0x48, 0x8b, 0x44, 0x24, 0x78, 0x8b, 0x40, 0x1c, 0x48, 0x8b, 0x4c, 
    0x24, 0x58, 0x48, 0x03, 0xc8, 0x48, 0x8b, 0xc1, 0x48, 0x89, 0x84, 0x24, 0x98, 0x00, 0x00, 0x00, 
    0x48, 0x8b, 0x84, 0x24, 0xa0, 0x00, 0x00, 0x00, 0x0f, 0xb7, 0x00, 0x48, 0x8b, 0x8c, 0x24, 0x98, 
    0x00, 0x00, 0x00, 0x48, 0x8d, 0x04, 0x81, 0x48, 0x89, 0x84, 0x24, 0x98, 0x00, 0x00, 0x00, 0x48, 
    0x8b, 0x84, 0x24, 0x98, 0x00, 0x00, 0x00, 0x8b, 0x00, 0x48, 0x8b, 0x4c, 0x24, 0x58, 0x48, 0x03, 
    0xc8, 0x48, 0x8b, 0xc1, 0x48, 0x89, 0x84, 0x24, 0x88, 0x00, 0x00, 0x00, 0xeb, 0x2d, 0x48, 0x8b, 
    0x84, 0x24, 0x80, 0x00, 0x00, 0x00, 0x48, 0x83, 0xc0, 0x04, 0x48, 0x89, 0x84, 0x24, 0x80, 0x00, 
    0x00, 0x00, 0x48, 0x8b, 0x84, 0x24, 0xa0, 0x00, 0x00, 0x00, 0x48, 0x83, 0xc0, 0x02, 0x48, 0x89, 
    0x84, 0x24, 0xa0, 0x00, 0x00, 0x00, 0xe9, 0x3e, 0xff, 0xff, 0xff, 0x48, 0x83, 0xbc, 0x24, 0x88, 
    0x00, 0x00, 0x00, 0x00, 0x74, 0x02, 0xeb, 0x12, 0x48, 0x8b, 0x44, 0x24, 0x68, 0x48, 0x8b, 0x00, 
    0x48, 0x89, 0x44, 0x24, 0x68, 0xe9, 0xd4, 0xfd, 0xff, 0xff, 0x48, 0x83, 0xbc, 0x24, 0x88, 0x00, 
    0x00, 0x00, 0x00, 0x75, 0x04, 0x33, 0xc0, 0xeb, 0x60, 0x48, 0x8b, 0x84, 0x24, 0xc0, 0x00, 0x00, 
    0x00, 0x48, 0x83, 0xc0, 0x10, 0x48, 0xc7, 0x44, 0x24, 0x48, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 
    0x44, 0x24, 0x40, 0x48, 0xc7, 0x44, 0x24, 0x38, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x84, 0x24, 
    0xc0, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x00, 0x48, 0x89, 0x44, 0x24, 0x30, 0x48, 0xc7, 0x44, 0x24, 
    0x28, 0x00, 0x00, 0x00, 0x00, 0x48, 0xc7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00, 0x45, 0x33, 
    0xc9, 0x45, 0x33, 0xc0, 0x33, 0xd2, 0x48, 0x8b, 0x84, 0x24, 0xc0, 0x00, 0x00, 0x00, 0x48, 0x8b, 
    0x48, 0x08, 0xff, 0x94, 0x24, 0x88, 0x00, 0x00, 0x00, 0x48, 0x81, 0xc4, 0xb8, 0x00, 0x00, 0x00, 
    0xc3, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 
    0x48, 0x89, 0x4c, 0x24, 0x08, 0x48, 0x83, 0xec, 0x38, 0x48, 0x8d, 0x0d, 0x03, 0x3d, 0x00, 0x00, 
    0xe8, 0x9b, 0x00, 0x00, 0x00, 0xc7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00, 0x8b, 0x4c, 0x24, 
    0x20, 0xe8, 0x5a, 0x00, 0x00, 0x00, 0x89, 0x44, 0x24, 0x20, 0x48, 0x8b, 0x44, 0x24, 0x40, 0x0f, 
    0xbe, 0x00, 0x8b, 0x4c, 0x24, 0x20, 0x03, 0xc8, 0x8b, 0xc1, 0x89, 0x44, 0x24, 0x20, 0x48, 0x8b, 
    0x44, 0x24, 0x40, 0x48, 0xff, 0xc0, 0x48, 0x89, 0x44, 0x24, 0x40, 0x48, 0x8b, 0x44, 0x24, 0x40, 
    0x0f, 0xbe, 0x00, 0x85, 0xc0, 0x75, 0xc6, 0x8b, 0x44, 0x24, 0x20, 0x48, 0x83, 0xc4, 0x38, 0xc3, 
    0x48, 0x83, 0xec, 0x28, 0x48, 0x8d, 0x0d, 0xa9, 0x3c, 0x00, 0x00, 0xe8, 0x40, 0x00, 0x00, 0x00, 
    0x48, 0x8b, 0x44, 0x24, 0x28, 0x48, 0x83, 0xc4, 0x28, 0xc3, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 
    0x89, 0x4c, 0x24, 0x08, 0x48, 0x83, 0xec, 0x28, 0x48, 0x8d, 0x0d, 0x84, 0x3c, 0x00, 0x00, 0xe8, 
    0x1c, 0x00, 0x00, 0x00, 0x8b, 0x44, 0x24, 0x30, 0xc1, 0xc8, 0x0d, 0x48, 0x83, 0xc4, 0x28, 0xc3, 
    0xc2, 0x00, 0x00, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 
    0x48, 0x89, 0x4c, 0x24, 0x08, 0x48, 0x83, 0xec, 0x38, 0x48, 0x8b, 0x44, 0x24, 0x40, 0x48, 0x89, 
    0x44, 0x24, 0x20, 0x48, 0x8b, 0x44, 0x24, 0x40, 0x0f, 0xb6, 0x00, 0x85, 0xc0, 0x74, 0x18, 0x83, 
    0x3d, 0x2a, 0x1c, 0x00, 0x00, 0x00, 0x74, 0x0f, 0xff, 0x15, 0x22, 0x0c, 0x00, 0x00, 0x39, 0x05, 
    0x1c, 0x1c, 0x00, 0x00, 0x75, 0x01, 0x90, 0x48, 0x83, 0xc4, 0x38, 0xc3, 0xff, 0x25, 0x0e, 0x0c, 
    0x00, 0x00, 
};