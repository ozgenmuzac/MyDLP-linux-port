#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
 .exit = cleanup_module,
#endif
 .arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0xbce771f0, "module_layout" },
	{ 0xf9fdaf8c, "kmalloc_caches" },
	{ 0xd0d8621b, "strlen" },
	{ 0x607c2726, "redirfs_register_filter" },
	{ 0xc3e2a23c, "redirfs_unregister_filter" },
	{ 0x105e2727, "__tracepoint_kmalloc" },
	{ 0x41344088, "param_get_charp" },
	{ 0x29baa0db, "redirfs_get_filename" },
	{ 0xa05c3909, "netlink_kernel_create" },
	{ 0xb72397d5, "printk" },
	{ 0x75cd5ec6, "netlink_kernel_release" },
	{ 0xb4390f9a, "mcount" },
	{ 0xa3ca6f45, "redirfs_put_path" },
	{ 0x184bfde7, "redirfs_set_operations" },
	{ 0x4cb3a103, "init_net" },
	{ 0x34934dec, "redirfs_add_path" },
	{ 0x91920ad0, "kmem_cache_alloc" },
	{ 0xfad27eee, "__alloc_skb" },
	{ 0xc66063ff, "path_lookup" },
	{ 0x36d7c24d, "path_put" },
	{ 0x6ad065f4, "param_set_charp" },
	{ 0x37a0cba, "kfree" },
	{ 0xf5446303, "redirfs_delete_filter" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=redirfs";


MODULE_INFO(srcversion, "6E0348BF8730304D162D0E0");
