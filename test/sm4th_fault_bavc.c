/*
 * Copyright 2026 The Tongsuo Project Authors. All Rights Reserved.
 * Licensed under the Apache License 2.0 (the "License").
 * You may obtain a copy at https://www.openssl.org/source/license.html
 *
 * Compile a private BAVC copy with a fixed allocation tag so the fault test
 * can track its allocations even when the library uses no-filenames.
 */
#define OPENSSL_FILE "sm4th/fault-bavc"
#define OPENSSL_LINE 0

#include "../crypto/sm4th/bavc.c"
