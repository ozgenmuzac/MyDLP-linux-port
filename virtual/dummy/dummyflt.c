/*
 * DummyFlt: Dummy Filter
 * Written by Frantisek Hrbata <frantisek.hrbata@redirfs.org>
 *
 * Copyright (C) 2008 Frantisek Hrbata
 * All rights reserved.
 *
 * This file is part of RedirFS.
 *
 * RedirFS is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * RedirFS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with RedirFS. If not, see <http://www.gnu.org/licenses/>.
 */

#include "/home/ozgen/Desktop/packages/redirfs-0.10/redirfs.h"
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>

#define DUMMYFLT_VERSION   "0.4"
#define NETLINK_USER	    31

static char *myPath;

module_param(myPath, charp, 0000);
MODULE_PARM_DESC(myPath, "Path");

struct sock *nl_sk = NULL; /*for creating a netlink socket, in other words, an initializer*/
struct nlmsghdr *nlh;
struct sk_buff *skb_out;
int pid; /*pid of sending process*/

struct address_space_operations *orig;
struct address_space_operations *my_space_operation;

static redirfs_filter dummyflt;

static struct redirfs_filter_info dummyflt_info = {
	.owner = THIS_MODULE,
	.name = "dummyflt",
	.priority = 500000000,/*kucuk numara yuksek priority, bunu en sonunda degistirmeli!*/
	.active = 1
};

static void *dummyflt_alloc(size_t size)
{
	void *p;
	
	p = kmalloc(size, GFP_KERNEL);
	if (!p)
		return NULL;

	memset(p, 0, size);

	return p;
}

/*int my_write_begin(struct file* mFile, struct address_space *mapping, loff_t pos, unsigned len, unsigned flags, struct page **pagep, void **fsdata)
{
	printk(KERN_INFO "my_write_begine girdi!!\n");
	return orig->write_begin(mFile, mapping, pos, len, flags, pagep, fsdata);
}

int my_write_end(struct file* mFile, struct address_space *mapping, loff_t pos, unsigned len, unsigned copied, struct page *pagep, void *fsdata)
{
	printk(KERN_INFO "my_write_ende girdi!!\n");
	return orig->write_end(mFile, mapping, pos, len, copied, pagep, fsdata);
}

int my_writepage(struct page *page, struct writeback_control *wbc)
{
	printk(KERN_INFO "my_writepage'a girdi!!\n");
	return orig->writepage(page, wbc);
}

enum redirfs_rv dummyflt_aio_write(redirfs_context context, struct redirfs_args *args)
{
	printk(KERN_INFO "Dummyflt_aio_write a girdi!\n");
	return REDIRFS_CONTINUE;
}*/

enum redirfs_rv dummyflt_write(redirfs_context context, struct redirfs_args *args)
{
	printk(KERN_INFO "Dummyflt_write a girdi\n");
	
	struct redirfs_path_info dummyflt_path_info2;
	struct nameidata ndTest;
	redirfs_path path2;
	int msgSize, res, rv, i;
	char *written_data;
	written_data = kmalloc(sizeof(char)*args->args.f_write.count, GFP_KERNEL);
	if(written_data == NULL)
	{
		printk(KERN_INFO "kmalloc failed\n");
		goto exit;
	}
	/*msgSize=args->args.f_write.count;*/
	msgSize = strlen(args->args.f_write.buf);
	
	skb_out = nlmsg_new(msgSize,0);
	if(!skb_out)
	{
		printk(KERN_ERR "Failed to allocate new skb\n");
	    goto exit;
	}
	
	if(copy_from_user(written_data, args->args.f_write.buf, msgSize))
	{
		printk(KERN_INFO "copy from user is failed\n");
		goto exit;
	}
	
	if(args->type.call == REDIRFS_PRECALL)
	{
		nlh=nlmsg_put(skb_out,0,0,NLMSG_DONE,msgSize,0);  
		NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
		strncpy(nlmsg_data(nlh), written_data, msgSize);

		res=nlmsg_unicast(nl_sk,skb_out,pid);

		if(res != 0)
			printk(KERN_INFO "Error while sending bak to user\n");
	}
	
	kfree(written_data);
	
	/*my_space_operation = kmalloc(sizeof(*my_space_operation), GFP_KERNEL);
	memcpy(my_space_operation, args->args.f_open.file->f_mapping->a_ops, sizeof(*my_space_operation));
	nrpages = args->args.f_write.file->f_mapping->nrpages;*/
	
	/*my_space_operation->write_begin = my_write_begin;
	my_space_operation->write_end = my_write_end;*/
	/*if(my_space_operation->writepage == NULL)
		printk(KERN_INFO "function is null!\n");
	
	orig = args->args.f_open.file->f_mapping->a_ops;
	args->args.f_open.file->f_mapping->a_ops = my_space_operation;*/
	
	/**************//*adding new path test. Successful!*/
	/*rv = path_lookup("/home/ozgen/Desktop/test4", LOOKUP_FOLLOW, &ndTest);
	if (rv) {
		printk(KERN_ERR "dummyflt: path2 lookup failed(%d)\n", rv);
		goto exit;
	}
	dummyflt_path_info2.dentry = ndTest.path.dentry;
	dummyflt_path_info2.mnt  = ndTest.path.mnt;
	dummyflt_path_info2.flags  = REDIRFS_PATH_INCLUDE;

	path2 = redirfs_add_path(dummyflt, &dummyflt_path_info2);
	if (IS_ERR(path2)) {
		rv = PTR_ERR(path2);
		printk(KERN_ERR "dummyflt: redirfs_set_path failed(%d)\n", rv);
		path_put(&ndTest.path);
		goto exit;
	}

	path_put(&ndTest.path);
	redirfs_put_path(path2);*/
	/**************/
	
	/* *args->args.f_write.pos += args->args.f_write.count;*/
	
exit:
	return REDIRFS_CONTINUE;
}

enum redirfs_rv dummyflt_open(redirfs_context context,
		struct redirfs_args *args)
{
	char *path;
	char *call;
	int rv;
	int res;
	
	int msg_size;
	
	
	path = dummyflt_alloc(sizeof(char) * PAGE_SIZE);
	if (!path)
		return REDIRFS_CONTINUE;

	rv = redirfs_get_filename(args->args.f_open.file->f_vfsmnt,
			args->args.f_open.file->f_dentry, path, PAGE_SIZE);

	if (rv) {
		printk(KERN_ERR "dummyflt: rfs_get_filename failed(%d)\n", rv);
		goto exit;
	}

	call = args->type.call == REDIRFS_PRECALL ? "precall" : "postcall";
	
	msg_size=strlen(path);
	skb_out = nlmsg_new(msg_size,0);
	if(!skb_out)
	{
		printk(KERN_ERR "Failed to allocate new skb\n");
	    goto exit;
	}
	if(args->type.call == REDIRFS_PRECALL)
	{
		nlh=nlmsg_put(skb_out,0,0,NLMSG_DONE,msg_size,0);  
		NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
		strncpy(nlmsg_data(nlh),path,msg_size);

		res=nlmsg_unicast(nl_sk,skb_out,pid);

		if(res != 0)
			printk(KERN_INFO "Error while sending bak to user\n");
	}
	/*my_space_operation = kmalloc(sizeof(*my_space_operation), GFP_KERNEL);
	memcpy(my_space_operation, args->args.f_open.file->f_mapping->a_ops, sizeof(*my_space_operation));
	nrpages = args->args.f_write.file->f_mapping->nrpages;*/
	
	/*my_space_operation->write_begin = my_write_begin;
	my_space_operation->write_end = my_write_end;*
	my_space_operation->writepage = my_writepage;
	
	orig = args->args.f_open.file->f_mapping->a_ops;
	args->args.f_open.file->f_mapping->a_ops = my_space_operation;*/
	
	printk(KERN_INFO "dummyflt: open: %s, call: %s\n", path, call);

exit:
	kfree(path);
	return REDIRFS_CONTINUE;
}

enum redirfs_rv dummyflt_release(redirfs_context context,
		struct redirfs_args *args)
{
	char *path;
	char *call;
	int rv;

	path = dummyflt_alloc(sizeof(char) * PAGE_SIZE);
	if (!path)
		return REDIRFS_CONTINUE;

	rv = redirfs_get_filename(args->args.f_release.file->f_vfsmnt,
			args->args.f_release.file->f_dentry, path, PAGE_SIZE);

	if (rv) {
		printk(KERN_ERR "dummyflt: rfs_get_filename failed(%d)\n", rv);
		goto exit;
	}

	call = args->type.call == REDIRFS_PRECALL ? "precall" : "postcall";

	printk(KERN_ALERT "dummyflt: release: %s, call: %s\n", path, call);

exit:
	kfree(path);
	return REDIRFS_CONTINUE;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)

enum redirfs_rv dummyflt_permission(redirfs_context context,
		struct redirfs_args *args)
{
	char *path;
	char *call;
	int rv;

	if (!args->args.i_permission.nd)
		return REDIRFS_CONTINUE;

	path = dummyflt_alloc(sizeof(char) * PAGE_SIZE);
	if (!path)
		return REDIRFS_CONTINUE;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25))
	rv = redirfs_get_filename(args->args.i_permission.nd->mnt,
			args->args.i_permission.nd->dentry, path, PAGE_SIZE);
#else
	rv = redirfs_get_filename(args->args.i_permission.nd->path.mnt,
			args->args.i_permission.nd->path.dentry, path, PAGE_SIZE);
#endif

	if (rv) {
		printk(KERN_ERR "dummyflt: rfs_get_filename failed(%d)\n", rv);
		goto exit;
	}

	call = args->type.call == REDIRFS_PRECALL ? "precall" : "postcall";

	printk(KERN_ALERT "dummyflt: permission: %s, call: %s\n", path, call);

exit:
	kfree(path);
	return REDIRFS_CONTINUE;
}

#endif

enum redirfs_rv dummyflt_lookup(redirfs_context context,
		struct redirfs_args *args)
{
	char *path;
	char *call;
	int rv;

	if (!args->args.i_lookup.nd)
		return REDIRFS_CONTINUE;

	path = dummyflt_alloc(sizeof(char) * PAGE_SIZE);
	if (!path)
		return REDIRFS_CONTINUE;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25))
	rv = redirfs_get_filename(args->args.i_lookup.nd->mnt,
			args->args.i_lookup.nd->dentry, path, PAGE_SIZE);
#else
	rv = redirfs_get_filename(args->args.i_lookup.nd->path.mnt,
			args->args.i_lookup.nd->path.dentry, path, PAGE_SIZE);

#endif

	if (rv) {
		printk(KERN_ERR "dummyflt: rfs_get_filename failed(%d)\n", rv);
		goto exit;
	}

	call = args->type.call == REDIRFS_PRECALL ? "precall" : "postcall";

	printk(KERN_ALERT "dummyflt: lookup: %s, dentry: %s, call: %s\n", path,
			call, args->args.i_lookup.dentry->d_name.name);

exit:
	kfree(path);
	return REDIRFS_CONTINUE;
}

static struct redirfs_op_info dummyflt_op_info[] = {
	{REDIRFS_REG_FOP_OPEN, dummyflt_open, dummyflt_open},
	{REDIRFS_REG_FOP_RELEASE, dummyflt_release, dummyflt_release},
	{REDIRFS_DIR_FOP_OPEN, dummyflt_open, dummyflt_open},
	{REDIRFS_DIR_FOP_RELEASE, dummyflt_release, dummyflt_release},
	{REDIRFS_REG_FOP_WRITE, dummyflt_write, dummyflt_write},
	{REDIRFS_FIFO_FOP_WRITE, dummyflt_write, dummyflt_write},
	{REDIRFS_BLK_FOP_WRITE, dummyflt_write, dummyflt_write},
	{REDIRFS_CHR_FOP_WRITE, dummyflt_write, dummyflt_write},
	{REDIRFS_LNK_FOP_WRITE, dummyflt_write, dummyflt_write},
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
	{REDIRFS_REG_IOP_PERMISSION, dummyflt_permission, dummyflt_permission},
	{REDIRFS_DIR_IOP_PERMISSION, dummyflt_permission, dummyflt_permission},
#endif
	{REDIRFS_DIR_IOP_LOOKUP, dummyflt_lookup, dummyflt_lookup},
	{REDIRFS_OP_END, NULL, NULL}
};

void initializer(struct sk_buff *skb)/*it is used for initializing for taking of user space process pid*/
{
	nlh=(struct nlmsghdr*)skb->data;
	printk(KERN_INFO "User Space Process is Registered and Says: %s\n",(char*)nlmsg_data(nlh));
	pid = nlh->nlmsg_pid;
}

static int __init dummyflt_init(void)
{
	
	struct redirfs_path_info dummyflt_path_info;
	struct nameidata nd;
	redirfs_path path;
	

	int err;
	int rv;

	dummyflt = redirfs_register_filter(&dummyflt_info);
	
	if (IS_ERR(dummyflt)) {
		rv = PTR_ERR(dummyflt);
		printk(KERN_ERR "dummyflt: register filter failed(%d)\n", rv);
		return rv;
	}
	
	nl_sk=netlink_kernel_create(&init_net, NETLINK_USER, 0, initializer, NULL, THIS_MODULE);
	if(!nl_sk)
	{
	    printk(KERN_ALERT "Error creating socket.\n");
	    return 0;
	}

	rv = redirfs_set_operations(dummyflt, dummyflt_op_info);
	if (rv) {
		printk(KERN_ERR "dummyflt: set operations failed(%d)\n", rv);
		goto error;
	}

	
	rv = path_lookup(myPath, LOOKUP_FOLLOW, &nd);
	if (rv) {
		printk(KERN_ERR "dummyflt: path lookup failed(%d)\n", rv);
		goto error;
	}

	dummyflt_path_info.dentry = nd.path.dentry;
	dummyflt_path_info.mnt  = nd.path.mnt;
	dummyflt_path_info.flags  = REDIRFS_PATH_INCLUDE;

	path = redirfs_add_path(dummyflt, &dummyflt_path_info);
	if (IS_ERR(path)) {
		rv = PTR_ERR(path);
		printk(KERN_ERR "dummyflt: redirfs_set_path failed(%d)\n", rv);
		path_put(&nd.path);
		goto error;
	}

	path_put(&nd.path);
	redirfs_put_path(path);
	

	printk(KERN_INFO "Dummy Filter Version "
			DUMMYFLT_VERSION " <www.redirfs.org>\n");
	return 0;
error:
	err = redirfs_unregister_filter(dummyflt);
	if (err) {
		printk(KERN_ERR "dummyflt: unregister filter "
				"failed(%d)\n", err);
		return 0;
	}
	redirfs_delete_filter(dummyflt);
	return rv;
}

static void __exit dummyflt_exit(void)
{
	printk(KERN_INFO "Dummy Filter unregistered!\n");
	netlink_kernel_release(nl_sk);
	redirfs_delete_filter(dummyflt);
}

module_init(dummyflt_init);
module_exit(dummyflt_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Frantisek Hrbata <frantisek.hrbata@redirfs.org>");
MODULE_DESCRIPTION("Dummy Filter Version " DUMMYFLT_VERSION "<www.redirfs.org>");

