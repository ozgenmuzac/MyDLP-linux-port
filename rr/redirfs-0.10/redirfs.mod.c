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
	{ 0xbce771f0, "module_layout" },
	{ 0x94a6467e, "kobject_put" },
	{ 0xfb69281a, "kset_create_and_add" },
	{ 0xe553c199, "kmem_cache_destroy" },
	{ 0xf9fdaf8c, "kmalloc_caches" },
	{ 0x12da5bb2, "__kmalloc" },
	{ 0xb279da12, "pv_lock_ops" },
	{ 0xd0d8621b, "strlen" },
	{ 0x224c9a18, "kobject_uevent" },
	{ 0x973873ab, "_spin_lock" },
	{ 0x105e2727, "__tracepoint_kmalloc" },
	{ 0xf73dba5e, "dput" },
	{ 0x3fbbd666, "dget_locked" },
	{ 0x3d329378, "mutex_unlock" },
	{ 0xf94e938b, "kobject_del" },
	{ 0xb3a4fd04, "inode_setattr" },
	{ 0xe2d5255a, "strcmp" },
	{ 0x94de3391, "kobject_create_and_add" },
	{ 0x9629486a, "per_cpu__cpu_number" },
	{ 0x20f1ef60, "__mutex_init" },
	{ 0xb72397d5, "printk" },
	{ 0x42224298, "sscanf" },
	{ 0xacdeb154, "__tracepoint_module_get" },
	{ 0xa1c76e0a, "_cond_resched" },
	{ 0xb6ed1e53, "strncpy" },
	{ 0xb4390f9a, "mcount" },
	{ 0xbd60391e, "kmem_cache_free" },
	{ 0x76ecad99, "mutex_lock" },
	{ 0xc254af48, "dcache_lock" },
	{ 0xcdf87af9, "kobject_add" },
	{ 0x1f9526ed, "module_put" },
	{ 0x91920ad0, "kmem_cache_alloc" },
	{ 0xc66063ff, "path_lookup" },
	{ 0x312e8c59, "fs_kobj" },
	{ 0x42cbd392, "mntput_no_expire" },
	{ 0xd0989504, "sysfs_create_file" },
	{ 0x9bcf13d2, "inode_change_ok" },
	{ 0x36d7c24d, "path_put" },
	{ 0x7ecb001b, "__per_cpu_offset" },
	{ 0xdd52a712, "kmem_cache_create" },
	{ 0x4971b1bd, "iput" },
	{ 0x37a0cba, "kfree" },
	{ 0xed1fa59d, "generic_permission" },
	{ 0xb95c1544, "follow_up" },
	{ 0x48d9e09e, "kobject_init" },
	{ 0xd86cdfe4, "sysfs_remove_file" },
	{ 0x876b18a4, "vfs_dq_transfer" },
	{ 0x701d0ebd, "snprintf" },
	{ 0x8235805b, "memmove" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "4CDE7E6B9E2BF1F9154D15A");
