#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

MODULE_LICENSE("GPL");

static int __init snout_init(void) {
  pr_info("snout init\n");
  return 0;
}

static void __exit snout_exit(void) {
  pr_info("snout exit\n");
  return;
}

module_init(snout_init);
module_exit(snout_exit);
