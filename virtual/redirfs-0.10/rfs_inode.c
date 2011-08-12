/*
 * RedirFS: Redirecting File System
 * Written by Frantisek Hrbata <frantisek.hrbata@redirfs.org>
 *
 * Copyright 2008 - 2010 Frantisek Hrbata
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

#include "rfs.h"

static rfs_kmem_cache_t *rfs_inode_cache = NULL;

static struct rfs_inode *rfs_inode_alloc(struct inode *inode)
{
	struct rfs_inode *rinode;
	
	/****/
	/*printk(KERN_INFO "rfs_inode.c // rfs_inode_alloc");
	/****/

	rinode = kmem_cache_zalloc(rfs_inode_cache, GFP_KERNEL);
	if (IS_ERR(rinode))
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&rinode->rdentries);
	INIT_LIST_HEAD(&rinode->data);
	rinode->inode = inode;
	rinode->op_old = inode->i_op;
	rinode->fop_old = inode->i_fop;
	spin_lock_init(&rinode->lock);
	rfs_mutex_init(&rinode->mutex);
	atomic_set(&rinode->count, 1);
	atomic_set(&rinode->nlink, 1);
	rinode->rdentries_nr = 0;

	if (inode->i_op)
		memcpy(&rinode->op_new, inode->i_op,
				sizeof(struct inode_operations));

	rinode->op_new.rename = rfs_rename;

	return rinode;
}

struct rfs_inode *rfs_inode_get(struct rfs_inode *rinode)
{
	/****/
	/*printk(KERN_INFO "rfs_inode.c // rfs_inode_get");
	/****/
	
	if (!rinode || IS_ERR(rinode))
		return NULL;

	BUG_ON(!atomic_read(&rinode->count));
	atomic_inc(&rinode->count);

	return rinode;
}

void rfs_inode_put(struct rfs_inode *rinode)
{
	/****/
	/*printk(KERN_INFO "rfs_inode.c // rfs_inode_put");
	/****/
	
	if (!rinode || IS_ERR(rinode))
		return;

	BUG_ON(!atomic_read(&rinode->count));
	if (!atomic_dec_and_test(&rinode->count))
		return;

	rfs_info_put(rinode->rinfo);
	rfs_data_remove(&rinode->data);
	kmem_cache_free(rfs_inode_cache, rinode);
}

struct rfs_inode *rfs_inode_add(struct inode *inode, struct rfs_info *rinfo)
{
	struct rfs_inode *ri_new;
	struct rfs_inode *ri;
	
	/****/
	/*printk(KERN_INFO "rfs_inode.c // rfs_inode_add");
	/****/

	if (!inode)
		return NULL;

	ri_new = rfs_inode_alloc(inode);
	if (IS_ERR(ri_new))
		return ri_new;

	spin_lock(&inode->i_lock);

	ri = rfs_inode_find(inode);
	if (!ri) {
		ri_new->rinfo = rfs_info_get(rinfo);
		if (!S_ISSOCK(inode->i_mode))
			inode->i_fop = &rfs_file_ops;

		inode->i_op = &ri_new->op_new;
		rfs_inode_get(ri_new);
		ri = rfs_inode_get(ri_new);
	} else
		atomic_inc(&ri->nlink);

	spin_unlock(&inode->i_lock);

	rfs_inode_put(ri_new);

	return ri;
}

void rfs_inode_del(struct rfs_inode *rinode)
{
	/****/
	/*printk(KERN_INFO "rfs_inode.c // rfs_inode_del");
	/****/
	
	if (!atomic_dec_and_test(&rinode->nlink))
		return;

	if (!S_ISSOCK(rinode->inode->i_mode))
		rinode->inode->i_fop = rinode->fop_old;

	rinode->inode->i_op = rinode->op_old;
	rfs_inode_put(rinode);
}

void rfs_inode_add_rdentry(struct rfs_inode *rinode, struct rfs_dentry *rdentry)
{
	/****/
	/*printk(KERN_INFO "rfs_inode.c // rfs_inode_add_rdentry");
	/****/
	
	rfs_mutex_lock(&rinode->mutex);
	rinode->rdentries_nr++;
	list_add_tail(&rdentry->rinode_list, &rinode->rdentries);
	rfs_mutex_unlock(&rinode->mutex);
	rfs_dentry_get(rdentry);
}

void rfs_inode_rem_rdentry(struct rfs_inode *rinode, struct rfs_dentry *rdentry)
{
	/****/
	/*printk(KERN_INFO "rfs_inode.c // rfs_inode_rem_rdentry");
	/****/
	
	rfs_mutex_lock(&rinode->mutex);
	if (list_empty(&rdentry->rinode_list)) {
		rfs_mutex_unlock(&rinode->mutex);
		return;
	}
	rinode->rdentries_nr--;
	list_del_init(&rdentry->rinode_list);
	rfs_mutex_unlock(&rinode->mutex);
	rfs_dentry_put(rdentry);
}

static struct rfs_chain *rfs_inode_join_rchains(struct rfs_inode *rinode)
{
	struct rfs_dentry *rdentry = NULL;
	struct rfs_info *rinfo = NULL;
	struct rfs_chain *rchain = NULL;
	struct rfs_chain *rchain_old = NULL;
	
	/****/
	/*printk(KERN_INFO "rfs_inode.c // rfs_inode_join_rchains");
	/****/

	list_for_each_entry(rdentry, &rinode->rdentries, rinode_list) {
		spin_lock(&rdentry->lock);
		rinfo = rfs_info_get(rdentry->rinfo);
		spin_unlock(&rdentry->lock);

		rchain = rfs_chain_join(rinfo->rchain, rchain_old);

		rfs_info_put(rinfo);
		rfs_chain_put(rchain_old);

		if (IS_ERR(rchain))
			return rchain;

		rchain_old = rchain;
	}

	return rchain;
}

static int rfs_inode_set_rinfo_fast(struct rfs_inode *rinode)
{
	struct rfs_dentry *rdentry;
	
	/****/
	/*printk(KERN_INFO "rfs_inode.c // rfs_inode_set_rinfo_fast");
	/****/

	if (!rinode->rdentries_nr)
		return 0;

	if (rinode->rdentries_nr > 1)
		return -1;

	rdentry = list_entry(rinode->rdentries.next, struct rfs_dentry, rinode_list);

	spin_lock(&rdentry->lock);
	spin_lock(&rinode->lock);
	rfs_info_put(rinode->rinfo);
	rinode->rinfo = rfs_info_get(rdentry->rinfo);
	spin_unlock(&rinode->lock);
	spin_unlock(&rdentry->lock);

	return 0;
}

struct rfs_info *rfs_inode_get_rinfo(struct rfs_inode *rinode)
{
	struct rfs_info *rinfo;
	
	/****/
	/*printk(KERN_INFO "rfs_inode.c // rfs_inode_get_rinfo");
	/****/

	spin_lock(&rinode->lock);
	rinfo = rfs_info_get(rinode->rinfo);
	spin_unlock(&rinode->lock);

	return rinfo;
}

int rfs_inode_set_rinfo(struct rfs_inode *rinode)
{
	struct rfs_chain *rchain;
	struct rfs_info *rinfo;
	struct rfs_ops *rops;
	int rv;
	
	/****/
	/*printk(KERN_INFO "rfs_inode.c // rfs_inode_set_rinfo");
	/****/

	if (!rinode)
		return 0;

	rfs_mutex_lock(&rinode->mutex);
	rv = rfs_inode_set_rinfo_fast(rinode);
	rfs_mutex_unlock(&rinode->mutex);
	if (!rv)
		return 0;

	rinfo = rfs_info_alloc(NULL, NULL);
	if (IS_ERR(rinfo))
		return PTR_ERR(rinfo);

	rops = rfs_ops_alloc();
	if (IS_ERR(rops)) {
		rfs_info_put(rinfo);
		return PTR_ERR(rops);
	}

	rinfo->rops = rops;

	rfs_mutex_lock(&rinode->mutex);
	rv = rfs_inode_set_rinfo_fast(rinode);
	if (!rv) {
		rfs_mutex_unlock(&rinode->mutex);
		rfs_info_put(rinfo);
		return 0;
	}

	rchain = rfs_inode_join_rchains(rinode);
	if (IS_ERR(rchain)) {
		rfs_mutex_unlock(&rinode->mutex);
		rfs_info_put(rinfo);
		return PTR_ERR(rchain);
	}

	rinfo->rchain = rchain;

	if (!rinfo->rchain) {
		rfs_info_put(rinfo);
		rinfo = rfs_info_get(rfs_info_none);
	}

	rfs_chain_ops(rinfo->rchain, rinfo->rops);
	spin_lock(&rinode->lock);
	rfs_info_put(rinode->rinfo);
	rinode->rinfo = rinfo;
	spin_unlock(&rinode->lock);
	rfs_mutex_unlock(&rinode->mutex);

	return 0;
}

int rfs_inode_cache_create(void)
{
	/****/
	/*printk(KERN_INFO "rfs_inode.c // rfs_inode_cache_create");
	/****/
	
	rfs_inode_cache = rfs_kmem_cache_create("rfs_inode_cache",
			sizeof(struct rfs_inode));

	if (!rfs_inode_cache)
		return -ENOMEM;

	return 0;
}

void rfs_inode_cache_destroy(void)
{
	/****/
	/*printk(KERN_INFO "rfs_inode.c // rfs_inode_cache_destroy");
	/****/
	
	kmem_cache_destroy(rfs_inode_cache);
}

static struct dentry *rfs_lookup(struct inode *dir, struct dentry *dentry,
		struct nameidata *nd)
{
	struct rfs_inode *rinode;
	struct rfs_info *rinfo;
	struct rfs_context rcont;
	struct redirfs_args rargs;
	struct dentry *dadd = dentry;
	
	/****/
	/*printk(KERN_INFO "rfs_inode.c // rfs_lookup");
	/****/

	if (S_ISDIR(dir->i_mode))
		rargs.type.id = REDIRFS_DIR_IOP_LOOKUP;
	else
		return ERR_PTR(-ENOTDIR);

	rinode = rfs_inode_find(dir);
	rinfo = rfs_inode_get_rinfo(rinode);
	rfs_context_init(&rcont, 0);

	rargs.args.i_lookup.dir = dir;
	rargs.args.i_lookup.dentry = dentry;
	rargs.args.i_lookup.nd = nd;

	if (!rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
		if (rinode->op_old && rinode->op_old->lookup)
			rargs.rv.rv_dentry = rinode->op_old->lookup(
					rargs.args.i_lookup.dir,
					rargs.args.i_lookup.dentry,
					rargs.args.i_lookup.nd);
		else
			rargs.rv.rv_dentry = ERR_PTR(-ENOSYS);
	}

	rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
	rfs_context_deinit(&rcont);

	if (IS_ERR(rargs.rv.rv_dentry))
		goto exit;

	if (rargs.rv.rv_dentry)
		dadd = rargs.rv.rv_dentry;

	if (rfs_dcache_rdentry_add(dadd, rinfo))
		BUG();
exit:
	rfs_inode_put(rinode);
	rfs_info_put(rinfo);
	return rargs.rv.rv_dentry;
}

static int rfs_mkdir(struct inode *dir, struct dentry *dentry, int mode)
{
	struct rfs_inode *rinode;
	struct rfs_info *rinfo;
	struct rfs_context rcont;
	struct redirfs_args rargs;
	
	/****/
	/*printk(KERN_INFO "rfs_inode.c // rfs_mkdir");
	/****/

	rinode = rfs_inode_find(dir);
	rinfo = rfs_inode_get_rinfo(rinode);
	rfs_context_init(&rcont, 0);

	if (S_ISDIR(dir->i_mode))
		rargs.type.id = REDIRFS_DIR_IOP_MKDIR;
	else
		BUG();

	rargs.args.i_mkdir.dir = dir;
	rargs.args.i_mkdir.dentry = dentry;
	rargs.args.i_mkdir.mode = mode;

	if (!rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
		if (rinode->op_old && rinode->op_old->mkdir)
			rargs.rv.rv_int = rinode->op_old->mkdir(
					rargs.args.i_mkdir.dir,
					rargs.args.i_mkdir.dentry,
					rargs.args.i_mkdir.mode);
		else
			rargs.rv.rv_int = -ENOSYS;
	}

	rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
	rfs_context_deinit(&rcont);

	if (!rargs.rv.rv_int) {
		if (rfs_dcache_rdentry_add(dentry, rinfo))
			BUG();
	}

	rfs_inode_put(rinode);
	rfs_info_put(rinfo);
	return rargs.rv.rv_int;
}

static int rfs_create(struct inode *dir, struct dentry *dentry, int mode,
		struct nameidata *nd)
{
	struct rfs_inode *rinode;
	struct rfs_info *rinfo;
	struct rfs_context rcont;
	struct redirfs_args rargs;
	
	/****/
	/*printk(KERN_INFO "rfs_inode.c // rfs_create");
	/****/

	rinode = rfs_inode_find(dir);
	rinfo = rfs_inode_get_rinfo(rinode);
	rfs_context_init(&rcont, 0);

	if (S_ISDIR(dir->i_mode))
		rargs.type.id = REDIRFS_DIR_IOP_CREATE;
	else
		BUG();

	rargs.args.i_create.dir = dir;
	rargs.args.i_create.dentry = dentry;
	rargs.args.i_create.mode = mode;
	rargs.args.i_create.nd = nd;

	if (!rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
		if (rinode->op_old && rinode->op_old->create)
			rargs.rv.rv_int = rinode->op_old->create(
					rargs.args.i_create.dir,
					rargs.args.i_create.dentry,
					rargs.args.i_create.mode,
					rargs.args.i_create.nd);
		else
			rargs.rv.rv_int = -ENOSYS;
	}

	rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
	rfs_context_deinit(&rcont);

	if (!rargs.rv.rv_int) {
		if (rfs_dcache_rdentry_add(dentry, rinfo))
			BUG();
	}

	rfs_inode_put(rinode);
	rfs_info_put(rinfo);
	return rargs.rv.rv_int;
}

static int rfs_link(struct dentry *old_dentry, struct inode *dir,
		struct dentry *dentry)
{
	struct rfs_inode *rinode;
	struct rfs_info *rinfo;
	struct rfs_context rcont;
	struct redirfs_args rargs;
	
	/****/
	/*printk(KERN_INFO "rfs_inode.c // rfs_link");
	/****/

	rinode = rfs_inode_find(dir);
	rinfo = rfs_inode_get_rinfo(rinode);
	rfs_context_init(&rcont, 0);

	if (S_ISDIR(dir->i_mode))
		rargs.type.id = REDIRFS_DIR_IOP_LINK;
	else
		BUG();

	rargs.args.i_link.old_dentry = old_dentry;
	rargs.args.i_link.dir = dir;
	rargs.args.i_link.dentry = dentry;

	if (!rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
		if (rinode->op_old && rinode->op_old->link)
			rargs.rv.rv_int = rinode->op_old->link(
					rargs.args.i_link.old_dentry,
					rargs.args.i_link.dir,
					rargs.args.i_link.dentry);
		else
			rargs.rv.rv_int = -ENOSYS;
	}

	rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
	rfs_context_deinit(&rcont);

	if (!rargs.rv.rv_int) {
		if (rfs_dcache_rdentry_add(dentry, rinfo))
			BUG();
	}

	rfs_inode_put(rinode);
	rfs_info_put(rinfo);
	return rargs.rv.rv_int;
}

static int rfs_symlink(struct inode *dir, struct dentry *dentry,
		const char *oldname)
{
	struct rfs_inode *rinode;
	struct rfs_info *rinfo;
	struct rfs_context rcont;
	struct redirfs_args rargs;
	
	/****/
	/*printk(KERN_INFO "rfs_inode.c // rfs_symlink");
	/****/

	rinode = rfs_inode_find(dir);
	rinfo = rfs_inode_get_rinfo(rinode);
	rfs_context_init(&rcont, 0);

	if (S_ISDIR(dir->i_mode))
		rargs.type.id = REDIRFS_DIR_IOP_SYMLINK;
	else
		BUG();

	rargs.args.i_symlink.dir = dir;
	rargs.args.i_symlink.dentry = dentry;
	rargs.args.i_symlink.oldname = oldname;

	if (!rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
		if (rinode->op_old && rinode->op_old->symlink)
			rargs.rv.rv_int = rinode->op_old->symlink(
					rargs.args.i_symlink.dir,
					rargs.args.i_symlink.dentry,
					rargs.args.i_symlink.oldname);
		else
			rargs.rv.rv_int = -ENOSYS;
	}

	rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
	rfs_context_deinit(&rcont);

	if (!rargs.rv.rv_int) {
		if (rfs_dcache_rdentry_add(dentry, rinfo))
			BUG();
	}

	rfs_inode_put(rinode);
	rfs_info_put(rinfo);
	return rargs.rv.rv_int;
}

static int rfs_mknod(struct inode * dir, struct dentry *dentry, int mode,
		dev_t rdev)
{
	struct rfs_inode *rinode;
	struct rfs_info *rinfo;
	struct rfs_context rcont;
	struct redirfs_args rargs;
	
	/****/
	/*printk(KERN_INFO "rfs_inode.c // rfs_mknod");
	/****/

	rinode = rfs_inode_find(dir);
	rinfo = rfs_inode_get_rinfo(rinode);
	rfs_context_init(&rcont, 0);

	if (S_ISDIR(dir->i_mode))
		rargs.type.id = REDIRFS_DIR_IOP_MKNOD;
	else
		BUG();

	rargs.args.i_mknod.dir = dir;
	rargs.args.i_mknod.dentry = dentry;
	rargs.args.i_mknod.mode = mode;
	rargs.args.i_mknod.rdev = rdev;

	if (!rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
		if (rinode->op_old && rinode->op_old->mknod)
			rargs.rv.rv_int = rinode->op_old->mknod(
					rargs.args.i_mknod.dir,
					rargs.args.i_mknod.dentry,
					rargs.args.i_mknod.mode,
					rargs.args.i_mknod.rdev);
		else
			rargs.rv.rv_int = -ENOSYS;
	}

	rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
	rfs_context_deinit(&rcont);

	if (!rargs.rv.rv_int) {
		if (rfs_dcache_rdentry_add(dentry, rinfo))
			BUG();
	}

	rfs_inode_put(rinode);
	rfs_info_put(rinfo);
	return rargs.rv.rv_int;
}

static int rfs_unlink(struct inode *inode, struct dentry *dentry)
{
	struct rfs_inode *rinode;
	struct rfs_info *rinfo;
	struct rfs_context rcont;
	struct redirfs_args rargs;
	
	/****/
	/*printk(KERN_INFO "rfs_inode.c // rfs_unlink");
	/****/

	rinode = rfs_inode_find(inode);
	rinfo = rfs_inode_get_rinfo(rinode);
	rfs_context_init(&rcont, 0);

	if (S_ISDIR(inode->i_mode))
		rargs.type.id = REDIRFS_DIR_IOP_UNLINK;
	else
		BUG();

	rargs.args.i_unlink.dir = inode;
	rargs.args.i_unlink.dentry = dentry;

	if (!rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
		if (rinode->op_old && rinode->op_old->unlink)
			rargs.rv.rv_int = rinode->op_old->unlink(
					rargs.args.i_unlink.dir,
					rargs.args.i_unlink.dentry);
		else
			rargs.rv.rv_int = -ENOSYS;
	}

	rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
	rfs_context_deinit(&rcont);

	rfs_inode_put(rinode);
	rfs_info_put(rinfo);
	return rargs.rv.rv_int;
}

static int rfs_rmdir(struct inode *inode, struct dentry *dentry)
{
	struct rfs_inode *rinode;
	struct rfs_info *rinfo;
	struct rfs_context rcont;
	struct redirfs_args rargs;
	
	/****/
	/*printk(KERN_INFO "rfs_inode.c // rfs_rmdir");
	/****/

	rinode = rfs_inode_find(inode);
	rinfo = rfs_inode_get_rinfo(rinode);
	rfs_context_init(&rcont, 0);

	if (S_ISDIR(inode->i_mode))
		rargs.type.id = REDIRFS_DIR_IOP_RMDIR;
	else
		BUG();

	rargs.args.i_unlink.dir = inode;
	rargs.args.i_unlink.dentry = dentry;

	if (!rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
		if (rinode->op_old && rinode->op_old->rmdir)
			rargs.rv.rv_int = rinode->op_old->rmdir(
					rargs.args.i_unlink.dir,
					rargs.args.i_unlink.dentry);
		else
			rargs.rv.rv_int = -ENOSYS;
	}

	rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
	rfs_context_deinit(&rcont);

	rfs_inode_put(rinode);
	rfs_info_put(rinfo);
	return rargs.rv.rv_int;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)

static int rfs_permission(struct inode *inode, int mask, struct nameidata *nd)
{
	struct rfs_inode *rinode;
	struct rfs_info *rinfo;
	struct rfs_context rcont;
	struct redirfs_args rargs;
	int submask;
	
	/****/
	/*printk(KERN_INFO "rfs_inode.c // rfs_permission");
	/****/

	submask = mask & ~MAY_APPEND;
	rinode = rfs_inode_find(inode);
	rinfo = rfs_inode_get_rinfo(rinode);
	rfs_context_init(&rcont, 0);

	if (S_ISREG(inode->i_mode))
		rargs.type.id = REDIRFS_REG_IOP_PERMISSION;
	else if (S_ISDIR(inode->i_mode))
		rargs.type.id = REDIRFS_DIR_IOP_PERMISSION;
	else if (S_ISLNK(inode->i_mode))
		rargs.type.id = REDIRFS_LNK_IOP_PERMISSION;
	else if (S_ISCHR(inode->i_mode))
		rargs.type.id = REDIRFS_CHR_IOP_PERMISSION;
	else if (S_ISBLK(inode->i_mode))
		rargs.type.id = REDIRFS_BLK_IOP_PERMISSION;
	else if (S_ISFIFO(inode->i_mode))
		rargs.type.id = REDIRFS_FIFO_IOP_PERMISSION;
	else 
		rargs.type.id = REDIRFS_SOCK_IOP_PERMISSION;

	rargs.args.i_permission.inode = inode;
	rargs.args.i_permission.mask = mask;
	rargs.args.i_permission.nd = nd;

	if (!rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
		if (rinode->op_old && rinode->op_old->permission)
			rargs.rv.rv_int = rinode->op_old->permission(
					rargs.args.i_permission.inode,
					rargs.args.i_permission.mask,
					rargs.args.i_permission.nd);
		else
			rargs.rv.rv_int = generic_permission(inode, submask,
					NULL);
	}

	rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
	rfs_context_deinit(&rcont);

	rfs_inode_put(rinode);
	rfs_info_put(rinfo);
	return rargs.rv.rv_int;
}

#else

static int rfs_permission(struct inode *inode, int mask)
{
	struct rfs_inode *rinode;
	struct rfs_info *rinfo;
	struct rfs_context rcont;
	struct redirfs_args rargs;
	int submask;
	
	/****/
	/*printk(KERN_INFO "rfs_inode.c // rfs_permission2");
	/****/

	submask = mask & ~MAY_APPEND;
	rinode = rfs_inode_find(inode);
	rinfo = rfs_inode_get_rinfo(rinode);
	rfs_context_init(&rcont, 0);

	if (S_ISREG(inode->i_mode))
		rargs.type.id = REDIRFS_REG_IOP_PERMISSION;
	else if (S_ISDIR(inode->i_mode))
		rargs.type.id = REDIRFS_DIR_IOP_PERMISSION;
	else if (S_ISLNK(inode->i_mode))
		rargs.type.id = REDIRFS_LNK_IOP_PERMISSION;
	else if (S_ISCHR(inode->i_mode))
		rargs.type.id = REDIRFS_CHR_IOP_PERMISSION;
	else if (S_ISBLK(inode->i_mode))
		rargs.type.id = REDIRFS_BLK_IOP_PERMISSION;
	else if (S_ISFIFO(inode->i_mode))
		rargs.type.id = REDIRFS_FIFO_IOP_PERMISSION;
	else 
		rargs.type.id = REDIRFS_SOCK_IOP_PERMISSION;

	rargs.args.i_permission.inode = inode;
	rargs.args.i_permission.mask = mask;

	if (!rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
		if (rinode->op_old && rinode->op_old->permission)
			rargs.rv.rv_int = rinode->op_old->permission(
					rargs.args.i_permission.inode,
					rargs.args.i_permission.mask);
		else
			rargs.rv.rv_int = generic_permission(inode, submask,
					NULL);
	}

	rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
	rfs_context_deinit(&rcont);

	rfs_inode_put(rinode);
	rfs_info_put(rinfo);
	return rargs.rv.rv_int;
}

#endif

static int rfs_setattr_default(struct dentry *dentry, struct iattr *iattr)
{
	struct inode *inode = dentry->d_inode;
	int rv;
	
	/****/
	/*printk(KERN_INFO "rfs_inode.c // rfs_setattr_default");
	/****/

	rv = inode_change_ok(inode, iattr);
	if (rv)
		return rv;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,34)
	if ((iattr->ia_valid & ATTR_UID && iattr->ia_uid != inode->i_uid) ||
	    (iattr->ia_valid & ATTR_GID && iattr->ia_gid != inode->i_gid))
		return rfs_dq_transfer(inode, iattr) ? -EDQUOT : 0;
#endif

	return inode_setattr(inode, iattr);
}

static int rfs_setattr(struct dentry *dentry, struct iattr *iattr)
{
	struct rfs_inode *rinode;
	struct rfs_info *rinfo;
	struct rfs_context rcont;
	struct redirfs_args rargs;
	
	/****/
	/*printk(KERN_INFO "rfs_inode.c // rfs_setattr");
	/****/

	rinode = rfs_inode_find(dentry->d_inode);
	rinfo = rfs_inode_get_rinfo(rinode);
	rfs_context_init(&rcont, 0);

	if (S_ISREG(dentry->d_inode->i_mode))
		rargs.type.id = REDIRFS_REG_IOP_SETATTR;
	else if (S_ISDIR(dentry->d_inode->i_mode))
		rargs.type.id = REDIRFS_DIR_IOP_SETATTR;
	else if (S_ISLNK(dentry->d_inode->i_mode))
		rargs.type.id = REDIRFS_LNK_IOP_SETATTR;
	else if (S_ISCHR(dentry->d_inode->i_mode))
		rargs.type.id = REDIRFS_CHR_IOP_SETATTR;
	else if (S_ISBLK(dentry->d_inode->i_mode))
		rargs.type.id = REDIRFS_BLK_IOP_SETATTR;
	else if (S_ISFIFO(dentry->d_inode->i_mode))
		rargs.type.id = REDIRFS_FIFO_IOP_SETATTR;
	else 
		rargs.type.id = REDIRFS_SOCK_IOP_SETATTR;

	rargs.args.i_setattr.dentry = dentry;
	rargs.args.i_setattr.iattr = iattr;

	if (!rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
		if (rinode->op_old && rinode->op_old->setattr)
			rargs.rv.rv_int = rinode->op_old->setattr(
					rargs.args.i_setattr.dentry,
					rargs.args.i_setattr.iattr);
		else 
			rargs.rv.rv_int = rfs_setattr_default(dentry, iattr);
	}

	rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
	rfs_context_deinit(&rcont);

	rfs_inode_put(rinode);
	rfs_info_put(rinfo);
	return rargs.rv.rv_int;
}

int rfs_rename(struct inode *old_dir, struct dentry *old_dentry,
		struct inode *new_dir, struct dentry *new_dentry)
{
	struct rfs_inode *rinode;
	struct rfs_info *rinfo;
	struct rfs_context rcont;
	struct redirfs_args rargs;
	
	/****/
	/*printk(KERN_INFO "rfs_inode.c // rfs_rename");
	/****/

	rinode = rfs_inode_find(old_dir);
	rinfo = rfs_inode_get_rinfo(rinode);
	rfs_context_init(&rcont, 0);

	if (S_ISDIR(old_dir->i_mode))
		rargs.type.id = REDIRFS_DIR_IOP_RENAME;
	else
		BUG();

	rargs.args.i_rename.old_dir = old_dir;
	rargs.args.i_rename.old_dentry = old_dentry;
	rargs.args.i_rename.new_dir = new_dir;
	rargs.args.i_rename.new_dentry = new_dentry;

	if (!rfs_precall_flts(rinfo->rchain, &rcont, &rargs)) {
		if (rinode->op_old && rinode->op_old->rename)
			rargs.rv.rv_int = rinode->op_old->rename(
					rargs.args.i_rename.old_dir,
					rargs.args.i_rename.old_dentry,
					rargs.args.i_rename.new_dir,
					rargs.args.i_rename.new_dentry);
		else
			rargs.rv.rv_int = -ENOSYS;
	}

	if (!rargs.rv.rv_int)
		rargs.rv.rv_int = rfs_fsrename(
				rargs.args.i_rename.old_dir,
				rargs.args.i_rename.old_dentry,
				rargs.args.i_rename.new_dir,
				rargs.args.i_rename.new_dentry);

	rfs_postcall_flts(rinfo->rchain, &rcont, &rargs);
	rfs_context_deinit(&rcont);

	rfs_inode_put(rinode);
	rfs_info_put(rinfo);
	return rargs.rv.rv_int;
}


static void rfs_inode_set_ops_reg(struct rfs_inode *rinode)
{
	/****/
	/*printk(KERN_INFO "rfs_inode.c // rfs_inode_set_ops_reg");
	/****/
	
	RFS_SET_IOP(rinode, REDIRFS_REG_IOP_PERMISSION, permission);
	RFS_SET_IOP(rinode, REDIRFS_REG_IOP_SETATTR, setattr);
}

static void rfs_inode_set_ops_dir(struct rfs_inode *rinode)
{
	/****/
	/*printk(KERN_INFO "rfs_inode.c // rfs_inode_set_ops_dir");
	/****/
	
	RFS_SET_IOP(rinode, REDIRFS_DIR_IOP_UNLINK, unlink);
	RFS_SET_IOP(rinode, REDIRFS_DIR_IOP_RMDIR, rmdir);
	RFS_SET_IOP(rinode, REDIRFS_DIR_IOP_PERMISSION, permission);
	RFS_SET_IOP(rinode, REDIRFS_DIR_IOP_SETATTR, setattr);

	RFS_SET_IOP_MGT(rinode, create);
	RFS_SET_IOP_MGT(rinode, link);
	RFS_SET_IOP_MGT(rinode, mknod);
	RFS_SET_IOP_MGT(rinode, symlink);

	rinode->op_new.lookup = rfs_lookup;
	rinode->op_new.mkdir = rfs_mkdir;
}

static void rfs_inode_set_ops_lnk(struct rfs_inode *rinode)
{
	/****/
	/*printk(KERN_INFO "rfs_inode.c // rfs_inode_set_ops_lnk");
	/****/
	
	RFS_SET_IOP(rinode, REDIRFS_LNK_IOP_PERMISSION, permission);
	RFS_SET_IOP(rinode, REDIRFS_LNK_IOP_SETATTR, setattr);
}

static void rfs_inode_set_ops_chr(struct rfs_inode *rinode)
{
	/****/
	/*printk(KERN_INFO "rfs_inode.c // rfs_inode_set_ops_chr");
	/****/
	
	RFS_SET_IOP(rinode, REDIRFS_CHR_IOP_PERMISSION, permission);
	RFS_SET_IOP(rinode, REDIRFS_CHR_IOP_SETATTR, setattr);
}

static void rfs_inode_set_ops_blk(struct rfs_inode *rinode)
{
	/****/
	/*printk(KERN_INFO "rfs_inode.c // rfs_inode_set_ops_blk");
	/****/
	
	RFS_SET_IOP(rinode, REDIRFS_BLK_IOP_PERMISSION, permission);
	RFS_SET_IOP(rinode, REDIRFS_BLK_IOP_SETATTR, setattr);
}

static void rfs_inode_set_ops_fifo(struct rfs_inode *rinode)
{
	/****/
	/*printk(KERN_INFO "rfs_inode.c // rfs_inode_set_ops_fifo");
	/****/
	
	RFS_SET_IOP(rinode, REDIRFS_FIFO_IOP_PERMISSION, permission);
	RFS_SET_IOP(rinode, REDIRFS_FIFO_IOP_SETATTR, setattr);
}

static void rfs_inode_set_ops_sock(struct rfs_inode *rinode)
{
	/****/
	/*printk(KERN_INFO "rfs_inode.c // rfs_inode_set_ops_sock");
	/****/
	
	RFS_SET_IOP(rinode, REDIRFS_SOCK_IOP_PERMISSION, permission);
	RFS_SET_IOP(rinode, REDIRFS_SOCK_IOP_SETATTR, setattr);
}

static void rfs_inode_set_aops_reg(struct rfs_inode *rinode)
{
	/****/
	/*printk(KERN_INFO "rfs_inode.c // rfs_inode_set_aops_reg");
	/****/
}

void rfs_inode_set_ops(struct rfs_inode *rinode)
{
	umode_t mode = rinode->inode->i_mode;

	/****/
	/*printk(KERN_INFO "rfs_inode.c // rfs_inode_set_ops");
	/****/

	spin_lock(&rinode->lock);

	if (S_ISREG(mode)) {
		rfs_inode_set_ops_reg(rinode);
		rfs_inode_set_aops_reg(rinode);

	} else if (S_ISDIR(mode))
		rfs_inode_set_ops_dir(rinode);

	else if (S_ISLNK(mode))
		rfs_inode_set_ops_lnk(rinode);

	else if (S_ISCHR(mode))
		rfs_inode_set_ops_chr(rinode);

	else if (S_ISBLK(mode))
		rfs_inode_set_ops_blk(rinode);

	else if (S_ISFIFO(mode))
		rfs_inode_set_ops_fifo(rinode);

	else if (S_ISSOCK(mode))
		rfs_inode_set_ops_sock(rinode);

	spin_unlock(&rinode->lock);
}

