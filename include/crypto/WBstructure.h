#ifndef _HSTRUCTURE_H_
#define _HSTRUCTURE_H_

#include <stdint.h>

//4bits
typedef struct M4
{
    uint8_t M[4];
}M4;

typedef struct V4
{
    uint8_t V;
}V4;

typedef struct Aff4
{
    M4 Mat;
    V4 Vec;
}Aff4;

//8bits
typedef struct M8
{
    uint8_t M[8];
}M8;

typedef struct V8
{
    uint8_t V;
}V8;

typedef struct Aff8
{
    M8 Mat;
    V8 Vec;
}Aff8;
//16bits
typedef struct M16
{
    uint16_t M[16];
}M16;

typedef struct V16
{
    uint16_t V;
}V16;

typedef struct Aff16
{
    M16 Mat;
    V16 Vec;
}Aff16;
//32bits
typedef struct M32
{
    uint32_t M[32];
}M32;

typedef struct V32
{
    uint32_t V;
}V32;

typedef struct Aff32
{
    M32 Mat;
    V32 Vec;
}Aff32;
//64bits
typedef struct M64
{
    uint64_t M[64];
}M64;

typedef struct V64
{
    uint64_t V;
}V64;

typedef struct Aff64
{
    M64 Mat;
    V64 Vec;
}Aff64;
//128bits
typedef struct M128
{
    uint64_t M[128][2];
}M128;

typedef struct V128
{
    uint64_t V[2];
}V128;

typedef struct Aff128
{
    M128 Mat;
    V128 Vec;
}Aff128;

#endif