/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2020-2022, Arm Limited
 */

#ifndef __ARM_FFA_USER_H
#define __ARM_FFA_USER_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define FFA_IOC_MAGIC	0xf0
#define FFA_IOC_BASE	0

/**
 * struct ffa_ioctl_ep_desc - Query endpoint ID
 * @uuid_ptr:	[in] Pointer to queried UUID. Format must be an RFC 4122 string,
 * 		i.e. "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".
 * @id:		[out] 16-bit ID of endpoint.
 */
struct ffa_ioctl_ep_desc {
	__u64 uuid_ptr;
	__u16 id;
};
#define FFA_IOC_GET_PART_ID	_IOWR(FFA_IOC_MAGIC, FFA_IOC_BASE + 0, \
				      struct ffa_ioctl_ep_desc)

/**
 * struct ffa_ioctl_msg_args - Send direct message request
 * @args:	[in/out] Arguments of FFA_MSG_SEND_DIRECT_REQ (w3-w7). If the
 * 		response is FFA_MSG_SEND_DIRECT_RESP, the received arguments are
 * 		returned in this field.
 * @dst_id:	[in] 16-bit ID of destination endpoint.
 */
struct ffa_ioctl_msg_args {
	__u64 args[5];
	__u16 dst_id;
};
#define FFA_IOC_MSG_SEND	_IOWR(FFA_IOC_MAGIC, FFA_IOC_BASE + 1, \
				      struct ffa_ioctl_msg_args)

/**
 * struct ffa_ioctl_shm_desc - Share/reclaim memory region
 * @handle:	[in/out] Handle assigned by the SPM. Output when used with
 * 		FFA_IOC_SHM_INIT, input when used with FFA_IOC_SHM_DEINIT.
 * @size:	[in/out] In: the required size of region in bytes. Out: the
 * 		actual region size allocated by the kernel. Unused on reclaim.
 * @dst_id:	[in] 16-bit ID of destination endpoint. Unused on reclaim.
 */
struct ffa_ioctl_shm_desc {
	__u64 handle;
	__u64 size;
	__u16 dst_id;
};
#define FFA_IOC_SHM_INIT	_IOWR(FFA_IOC_MAGIC, FFA_IOC_BASE + 2, \
				      struct ffa_ioctl_shm_desc)

#define FFA_IOC_SHM_DEINIT	_IOW(FFA_IOC_MAGIC, FFA_IOC_BASE + 3, \
				     struct ffa_ioctl_shm_desc)

/**
 * struct ffa_ioctl_buf_desc - Read/write shared memory region
 * @handle:	[in] Handle of the memory region.
 * @buf_ptr:	[in] Pointer to user space buffer. Data is copied from/to this
 * 		buffer to/from the memory region shared with the given endpoint.
 * @buf_len:	[in] Length of read/write in bytes.
 */
struct ffa_ioctl_buf_desc {
	__u64 handle;
	__u64 buf_ptr;
	__u64 buf_len;
};
#define FFA_IOC_SHM_READ	_IOW(FFA_IOC_MAGIC, FFA_IOC_BASE + 4, \
				     struct ffa_ioctl_buf_desc)

#define FFA_IOC_SHM_WRITE	_IOW(FFA_IOC_MAGIC, FFA_IOC_BASE + 5, \
				     struct ffa_ioctl_buf_desc)

#endif /* __ARM_FFA_USER_H */
