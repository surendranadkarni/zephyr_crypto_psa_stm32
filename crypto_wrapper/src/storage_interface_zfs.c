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
#include <zephyr/sys/reboot.h>
#include <zephyr/device.h>
#include <string.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/storage/flash_map.h>
#include <zephyr/fs/zms.h>
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(key_storage, LOG_LEVEL_DBG);

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
#ifndef PSA_ERROR_IO_ERROR
#define PSA_ERROR_IO_ERROR ((psa_status_t)-4)
#endif

#define ZMS_PARTITION        storage_partition
#define ZMS_PARTITION_DEVICE FIXED_PARTITION_DEVICE(ZMS_PARTITION)
#define ZMS_PARTITION_OFFSET FIXED_PARTITION_OFFSET(ZMS_PARTITION)

#define IP_ADDRESS_ID 1
#define KEY_VALUE_ID  0xbeefdead
#define CNT_ID        2
#define LONG_DATA_ID  3

static struct zms_fs fs;
/* Public API implementations */

psa_status_t storage_set(uint64_t obj_uid,
                         uint32_t obj_length,
                         const void *p_obj)
{
    int rc;
    if (p_obj == NULL) {
        LOG_ERR("storage_set: p_obj is NULL");
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (obj_length > STORAGE_MAX_ITEM_SIZE) {
        LOG_ERR("storage_set: obj_length %u exceeds max %u",
                obj_length, STORAGE_MAX_ITEM_SIZE);
        return PSA_ERROR_INSUFFICIENT_STORAGE;
    }

    rc = zms_write(&fs, obj_uid, (void*)p_obj, obj_length);
    if (rc < 0) {
        LOG_ERR("storage_set: failed to write uid 0x%llx, rc=%d", obj_uid, rc);
        return PSA_ERROR_IO_ERROR;
    }
    LOG_INF("storage_set: stored uid 0x%llx, size %u", obj_uid, obj_length);
    if(rc < obj_length) {
        LOG_ERR("storage_set: wrote %u bytes, requested %u bytes", rc, obj_length);
        return PSA_ERROR_IO_ERROR;
    }
    LOG_HEXDUMP_DBG(p_obj, obj_length, "Contents of p_obj");
    LOG_INF("storage_set: stored uid 0x%llx, size %u", obj_uid, obj_length);
    return PSA_SUCCESS;
}

psa_status_t storage_get(uint64_t obj_uid,
                         uint32_t obj_offset,
                         uint32_t obj_length,
                         void *p_obj)
{
    #warning "Check stack usage for this function"
    uint8_t buf[128];
    int rc;
    if (p_obj == NULL) {
        LOG_INF("storage_get: p_obj is NULL");
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if(obj_offset + obj_length > sizeof(buf)) {
        LOG_ERR("storage_get: offset %u + length %u exceeds buffer size %u", obj_offset, obj_length, sizeof(buf));
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    rc = zms_read(&fs, obj_uid, buf, sizeof(buf));
    if (rc < 0) {
        LOG_ERR("storage_get: failed to read uid 0x%llx, rc=%d", obj_uid, rc);
        return PSA_ERROR_IO_ERROR;
    }
    if(rc < obj_offset + obj_length) {
        LOG_ERR("storage_get: read %u bytes, requested %u bytes", rc, obj_offset + obj_length);
        return PSA_ERROR_IO_ERROR;
    }
    void *p_obj_temp = buf + sizeof(its_obj_info_t);
    LOG_HEXDUMP_DBG(p_obj_temp, obj_length, "Contents of p_obj_temp");
    memcpy(p_obj, p_obj_temp + obj_offset, obj_length);
    LOG_INF("storage_get: retrieved uid 0x%llx, offset %u, requested %u, copied %u",
            obj_uid, obj_offset, obj_length, obj_length);
    return PSA_SUCCESS;
}

psa_status_t storage_get_info(uint64_t obj_uid,
                              void *p_obj_info,
                              uint32_t obj_info_size)
{
    int rc;
    if(p_obj_info == NULL) {
        LOG_ERR("storage_get_info: p_obj_info is NULL");
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    rc = zms_read(&fs, obj_uid, (void*)p_obj_info, obj_info_size);
    if (rc < 0) {
        LOG_ERR("storage_get_info: failed to read uid 0x%llx, rc=%d", obj_uid, rc);
        return PSA_ERROR_IO_ERROR;
    }   
    if(rc < obj_info_size) {
        LOG_ERR("storage_get_info: read %u bytes, requested %u bytes", rc, obj_info_size);
        return PSA_ERROR_IO_ERROR;
    }
    LOG_INF("storage_get_info: uid 0x%llx size %u", obj_uid, rc);
    LOG_HEXDUMP_DBG(p_obj_info, obj_info_size, "Contents of p_obj_info");
    return PSA_SUCCESS;
}

psa_status_t storage_remove(uint64_t obj_uid, uint32_t obj_size)
{
    (void)obj_size; /* unused in this dummy implementation */
    int rc;
    rc = zms_delete(&fs, obj_uid);
    if (rc < 0) {
        LOG_ERR("storage_remove: failed to erase uid 0x%llx, rc=%d", obj_uid, rc);
        return PSA_ERROR_IO_ERROR;
    }
    LOG_INF("storage_remove: removed uid 0x%llx", obj_uid);
    return PSA_SUCCESS;
}

static int delete_and_verify_items(uint64_t id)
{
	int rc = 0;

	rc = zms_delete(&fs, id);
	if (rc) {
		goto error1;
	}
	rc = zms_get_data_length(&fs, id);
	if (rc > 0) {
		goto error2;
	}
    return 0;
error1:
	printk("Error while deleting item rc=%d\n", rc);
	return rc;
error2:
	printk("Error, Delete failed item should not be present\n");
	return -1;
}

static int storage_init(void)
{
	/* define the zms file system by settings with:
	 *	sector_size equal to the pagesize,
	 *	3 sectors
	 *	starting at ZMS_PARTITION_OFFSET
	 */
    int rc;
    struct flash_pages_info info;
    memset(&info, 0, sizeof(info));
    fs.flash_device = ZMS_PARTITION_DEVICE;
    if (!device_is_ready(fs.flash_device)) {
        LOG_ERR("Storage device %s is not ready\n", fs.flash_device->name);
        return -ENOSPC;
    }
    fs.offset = ZMS_PARTITION_OFFSET;
    rc = flash_get_page_info_by_offs(fs.flash_device, fs.offset, &info);
    if (rc) {
        LOG_ERR("Unable to get page info, rc=%d\n", rc);
        return -EIO;
    }
    fs.sector_size = info.size;
    fs.sector_count = 4U;
    rc = zms_mount(&fs);
    if (rc) {
        LOG_ERR("Storage Init failed, rc=%d\n", rc);
        return -EIO;
    }
    //
    // 
    //delete_and_verify_items(0x1fff0001); // delete the key from storage
    return 0;
}




SYS_INIT(storage_init,APPLICATION,0);