/*
** Copyright (c) 2017, Intel Corporation.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/
#ifndef DPI_HYPERSCAN_COMMON_H
#define DPI_HYPERSCAN_COMMON_H

#include <hs/hs.h>

typedef struct dpi_hs_summary_ {
    uint32_t db_count; // number of databases
    uint32_t db_bytes;       // total bytes compiled
    uint32_t scratch_size;   // size of scratch space
} dpi_hs_summary_t;

void HyperscanActivate(void *dlpdetector);
void HyperscanActivateMpse(void *dlpdetector);
void HyperscanActivatePcre(void *dlpdetector);
#endif
