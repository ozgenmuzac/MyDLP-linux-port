#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .init = init_module,
 .arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x33204b9b, "module_layout" },
	{ 0xf9b50079, "kobject_put" },
	{ 0x17cdf383, "kset_create_and_add" },
	{ 0xd17b8eec, "kmem_cache_destroy" },
	{ 0xa71c0aae, "kmalloc_caches" },
	{ 0x5a34a45c, "__kmalloc" },
	{ 0xb279da12, "pv_lock_ops" },
	{ 0x25ec1b28, "strlen" },
	{ 0x56f3cb05, "kobject_uevent" },
	{ 0x973873ab, "_spin_lock" },
	{ 0x105e2727, "__tracepoint_kmalloc" },
	{ 0xbf39538e, "dput" },
	{ 0xff2a2190, "dget_locked" },
	{ 0x88cfd52, "mutex_unlock" },
	{ 0xe85060c1, "kobject_del" },
	{ 0x6d6af7e8, "inode_setattr" },
	{ 0xe2d5255a, "strcmp" },
	{ 0xb87dd3df, "kobject_create_and_add" },
	{ 0x9629486a, "per_cpu__cpu_number" },
	{ 0xf0cd0281, "__mutex_init" },
	{ 0xea147363, "printk" },
	{ 0x42224298, "sscanf" },
	{ 0xacdeb154, "__tracepoint_module_get" },
	{ 0xa1c76e0a, "_cond_resched" },
	{ 0x7ec9bfbc, "strncpy" },
	{ 0xb4390f9a, "mcount" },
	{ 0xdb2696d5, "kmem_cache_free" },
	{ 0xc5fb3dd6, "mutex_lock" },
	{ 0xc254af48, "dcache_lock" },
	{ 0x5e4307a0, "kobject_add" },
	{ 0x48ae03c3, "module_put" },
	{ 0x5b8613c6, "kmem_cache_alloc" },
	{ 0xa17f6281, "path_lookup" },
	{ 0xfd14c8f9, "fs_kobj" },
	{ 0xfb357e77, "mntput_no_expire" },
	{ 0x54c39993, "sysfs_create_file" },
	{ 0x7eda5964, "inode_change_ok" },
	{ 0x9dc1cd1c, "path_put" },
	{ 0xc5844fb8, "__per_cpu_offset" },
	{ 0x6dfd3cf1, "kmem_cache_create" },
	{ 0x7971af11, "iput" },
	{ 0x37a0cba, "kfree" },
	{ 0x4c88c69b, "generic_permission" },
	{ 0xa6ecefd5, "follow_up" },
	{ 0x236c8c64, "memcpy" },
	{ 0x298d368, "kobject_init" },
	{ 0xfa24ba0d, "sysfs_remove_file" },
	{ 0xfc597635, "vfs_dq_transfer" },
	{ 0x9edbecae, "snprintf" },
	{ 0xa3a5be95, "memmove" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "40F37A94606BDD6DCCF54EB");
