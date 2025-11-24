/**
  ******************************************************************************
  * @file    storage_interface.c
  * @author  Surendra Nadkarni
  * @brief   Implementation of storage interface
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2024 Surendra Nadkarni.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
#include "storage_interface.h"
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <zephyr/init.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(storage, LOG_LEVEL_DBG);

/* Simple in-RAM storage parameters */
#define STORAGE_MAX_ENTRIES      8U
#define STORAGE_MAX_ITEM_SIZE    1024U

/* Ensure PSA status macros exist (assumes psa_status_t is defined by included headers) */
#ifndef PSA_SUCCESS
#define PSA_SUCCESS ((psa_status_t)0)
#endif
#ifndef PSA_ERROR_INVALID_ARGUMENT
#define PSA_ERROR_INVALID_ARGUMENT ((psa_status_t)-1)
#endif
#ifndef PSA_ERROR_DOES_NOT_EXIST
#define PSA_ERROR_DOES_NOT_EXIST ((psa_status_t)-2)
#endif
#ifndef PSA_ERROR_INSUFFICIENT_STORAGE
#define PSA_ERROR_INSUFFICIENT_STORAGE ((psa_status_t)-3)
#endif

typedef struct {
    bool        used;
    uint64_t    uid;
    uint32_t    size;
    uint8_t     data[STORAGE_MAX_ITEM_SIZE];
} storage_entry_t;

static storage_entry_t storage_table[STORAGE_MAX_ENTRIES] = {0};

/* Helper: find entry index by uid, -1 if not found */
static int find_entry(uint64_t uid)
{
    for (int i = 0; i < (int)STORAGE_MAX_ENTRIES; i++) {
        if (storage_table[i].used && storage_table[i].uid == uid) {
            return i;
        }
    }
    return -1;
}

/* Helper: find free slot index, -1 if none */
static int find_free_slot(void)
{
    for (int i = 0; i < (int)STORAGE_MAX_ENTRIES; i++) {
        if (!storage_table[i].used) {
            return i;
        }
    }
    return -1;
}

/* Public API implementations */

psa_status_t storage_set(uint64_t obj_uid,
                         uint32_t obj_length,
                         const void *p_obj)
{
    if (p_obj == NULL) {
        LOG_ERR("storage_set: p_obj is NULL");
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (obj_length > STORAGE_MAX_ITEM_SIZE) {
        LOG_ERR("storage_set: obj_length %u exceeds max %u",
                obj_length, STORAGE_MAX_ITEM_SIZE);
        return PSA_ERROR_INSUFFICIENT_STORAGE;
    }

    int idx = find_entry(obj_uid);
    if (idx < 0) {
        idx = find_free_slot();
        if (idx < 0) {
            LOG_ERR("storage_set: no free storage slots");
            return PSA_ERROR_INSUFFICIENT_STORAGE;
        }
    }

    /* store/overwrite */
    storage_table[idx].used = true;
    storage_table[idx].uid = obj_uid;
    storage_table[idx].size = obj_length;
    memcpy(storage_table[idx].data, p_obj, obj_length);
    /* zero remainder for deterministic behaviour */
    if (obj_length < STORAGE_MAX_ITEM_SIZE) {
        memset(storage_table[idx].data + obj_length, 0, STORAGE_MAX_ITEM_SIZE - obj_length);
    }
    LOG_INF("storage_set: stored uid 0x%llx, size %u at index %d",
            obj_uid, obj_length, idx);
    return PSA_SUCCESS;
}

psa_status_t storage_get(uint64_t obj_uid,
                         uint32_t obj_offset,
                         uint32_t obj_length,
                         void *p_obj)
{
    if (p_obj == NULL) {
        LOG_INF("storage_get: p_obj is NULL");
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    int idx = find_entry(obj_uid);
    if (idx < 0) {
        LOG_INF("storage_get: uid 0x%llx not found", obj_uid);
        return PSA_ERROR_DOES_NOT_EXIST;
    }

    uint32_t stored = storage_table[idx].size;
    if (obj_offset > stored) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    uint32_t avail = stored - obj_offset;
    uint32_t to_copy = (obj_length > avail) ? avail : obj_length;

    if (to_copy > 0) {
        memcpy(p_obj, storage_table[idx].data + obj_offset, to_copy);
    }
    LOG_INF("storage_get: retrieved uid 0x%llx, offset %u, requested %u, copied %u",
            obj_uid, obj_offset, obj_length, to_copy);
    /* If caller requested more than available, return success but only copied avail bytes.
       Caller can infer actual size via storage_get_info. */
    return PSA_SUCCESS;
}

psa_status_t storage_get_info(uint64_t obj_uid,
                              void *p_obj_info,
                              uint32_t obj_info_size)
{
    int idx = find_entry(obj_uid);
    if (idx < 0) {
        LOG_ERR("storage_get_info: uid 0x%llx not found", obj_uid);
        return PSA_ERROR_DOES_NOT_EXIST;
    }
    uint32_t stored_size = storage_table[idx].size;
    uint8_t *data_ptr = storage_table[idx].data;
    LOG_INF("storage_get_info: uid 0x%llx size %u data_ptr %p",
            obj_uid, stored_size, (void*)data_ptr);
    /* Minimal info support: if buffer is at least 4 bytes, return stored size as uint32_t */
    if (p_obj_info == NULL || obj_info_size > stored_size) {
        LOG_ERR("storage_get_info: invalid p_obj_info or size %u", obj_info_size);
        return PSA_ERROR_INVALID_ARGUMENT;
    }
      
    memcpy(p_obj_info, data_ptr, obj_info_size);
    LOG_INF("storage_get_info: uid 0x%llx size %u", obj_uid, stored_size);
    return PSA_SUCCESS;
}

psa_status_t storage_remove(uint64_t obj_uid, uint32_t obj_size)
{
    (void)obj_size; /* unused in this dummy implementation */

    int idx = find_entry(obj_uid);
    if (idx < 0) {
        LOG_ERR("storage_remove: uid 0x%llx not found", obj_uid);
        return PSA_ERROR_DOES_NOT_EXIST;
    }

    /* clear entry */
    memset(&storage_table[idx], 0, sizeof(storage_table[idx]));
    LOG_INF("storage_remove: removed uid 0x%llx at index %d",
            obj_uid, idx);
    return PSA_SUCCESS;
}

static int storage_init(void)
{
    for (int i = 0; i < (int)STORAGE_MAX_ENTRIES; i++) {
        storage_table[i].used = false;
        storage_table[i].uid = 0;
        storage_table[i].size = 0;
        memset(storage_table[i].data, 0xFF, sizeof(storage_table[i].data));
    }
    return 0;
}

SYS_INIT(storage_init,APPLICATION,0);