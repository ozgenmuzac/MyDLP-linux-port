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
	{ 0x33204b9b, "module_layout" },
	{ 0xa71c0aae, "kmalloc_caches" },
	{ 0x25ec1b28, "strlen" },
	{ 0xb30dab9f, "redirfs_register_filter" },
	{ 0xc3e2a23c, "redirfs_unregister_filter" },
	{ 0x105e2727, "__tracepoint_kmalloc" },
	{ 0x2ba20519, "redirfs_get_filename" },
	{ 0x47639140, "netlink_kernel_create" },
	{ 0xde0bdcff, "memset" },
	{ 0xea147363, "printk" },
	{ 0xa84ca8e9, "netlink_kernel_release" },
	{ 0x7ec9bfbc, "strncpy" },
	{ 0xb4390f9a, "mcount" },
	{ 0xa3ca6f45, "redirfs_put_path" },
	{ 0xce327294, "redirfs_set_operations" },
	{ 0x3b2de66b, "netlink_unicast" },
	{ 0x984d832f, "init_net" },
	{ 0xc6addb67, "redirfs_add_path" },
	{ 0x5b8613c6, "kmem_cache_alloc" },
	{ 0xacf65cf5, "__alloc_skb" },
	{ 0xa17f6281, "path_lookup" },
	{ 0x9dc1cd1c, "path_put" },
	{ 0x37a0cba, "kfree" },
	{ 0xf5446303, "redirfs_delete_filter" },
	{ 0xd615d9f8, "skb_put" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=redirfs";


MODULE_INFO(srcversion, "E78CD1EBD326C32A2988E24");
