// SPDX-License-Identifier: GPL-2.0

#ifndef __PERMS_H
#define __PERMS_H

// https://elixir.bootlin.com/linux/v5.10.178/source/tools/include/nolibc/nolibc.h#L446
/* fcntl / open */
#define O_RDONLY            0
#define O_WRONLY            1
#define O_RDWR              2
#define O_CREAT          0x40
#define O_EXCL           0x80
#define O_NOCTTY        0x100
#define O_TRUNC         0x200
#define O_APPEND        0x400
#define O_NONBLOCK      0x800
#define O_DIRECTORY   0x10000

// https://elixir.bootlin.com/linux/v5.10.178/source/include/linux/fs.h#L95
#define MAY_EXEC		0x00000001
#define MAY_WRITE		0x00000002
#define MAY_READ		0x00000004
#define MAY_APPEND	0x00000008
#define MAY_ACCESS	0x00000010
#define MAY_OPEN		0x00000020
#define MAY_CHDIR		0x00000040
#define FMODE_READ  0x1
#define FMODE_WRITE 0x2

// https://elixir.bootlin.com/linux/v5.10.178/source/security/apparmor/include/perms.h#L16
// https://elixir.bootlin.com/linux/v5.10.178/source/security/apparmor/include/net.h#L72
#define AA_MAY_EXEC     MAY_EXEC
#define AA_MAY_WRITE  	MAY_WRITE
#define AA_MAY_READ     MAY_READ
#define AA_MAY_APPEND		MAY_APPEND
#define AA_MAY_CREATE   0x0010
#define AA_MAY_RENAME   0x0080
#define AA_MAY_LINK		  0x00040000

#endif /* __PERMS_H */