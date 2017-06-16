/*
 * pi3's Linux kernel Runtime Guard
 *
 * Component:
 *  - Red-black tree for keeping track protected inodes structure
 *
 * Notes:
 *  - Make sence with own kmem_cache_* allocation
 *
 * Timeline:
 *  - Created: 03.X.2016
 *
 * Author:
 *  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
 *
 */

#ifndef P_LKRG_PROTECTED_INODES_RB_TREE_H
#define P_LKRG_PROTECTED_INODES_RB_TREE_H

#define p_alloc_inodes()      kmem_cache_alloc(p_inodes_cache, GFP_ATOMIC)
#define p_free_inodes(name)   kmem_cache_free(p_inodes_cache, (void *)(name))

#ifdef P_LKRG_DEBUG
#define P_DUMP_RB_INODES_TREE                                                                            \
do {                                                                                                     \
   struct rb_node *p_node;                                                                               \
                                                                                                         \
   for (p_node = rb_first(&p_global_inodes_root); p_node; p_node = rb_next(p_node))                      \
      p_print_log(P_LKRG_DBG, "inode => 0x%p\n",                                                         \
                                          rb_entry(p_node, struct p_protected_inode, p_rb)->p_inode);    \
} while(0);
#endif

struct p_protected_inode {

   struct rb_node p_rb;
   struct inode *p_inode;
   struct inode *p_parent_inode;

   const struct inode_operations *p_inode_orig;
   struct inode_operations p_inode_new;

   const struct file_operations *p_file_orig;
   struct file_operations p_file_new;

   kuid_t p_iuid;
   kgid_t p_igid;

   unsigned int p_opt; /* Protected File / Protected Logs*/

};

extern struct kmem_cache *p_inodes_cache;
extern struct rb_root p_global_inodes_root;


static inline void p_rb_init_inode_node(struct rb_node *rb) {

// STRONG_DEBUG
#ifdef P_LKRG_DEBUG
   p_print_log(P_LKRG_STRONG_DBG,
          "Entering function <p_rb_init_inode_node>\n");
#endif

   rb->__rb_parent_color = 0;
   rb->rb_right = NULL;
   rb->rb_left = NULL;
   RB_CLEAR_NODE(rb);

// STRONG_DEBUG
#ifdef P_LKRG_DEBUG
   p_print_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_rb_init_inode_node>\n");
#endif
}

static inline void p_iget_file(struct inode *inode) {

#ifdef P_LKRG_DEBUG
   p_print_log(P_LKRG_STRONG_DBG,
          "Entering function <p_iget_file>\n");
#endif

   /* Increment reference counter */
   atomic_inc(&inode->i_count);

   /* Set S_IMMUTABLE flag for inode */
   inode->i_flags |= S_IMMUTABLE;

   /* Set user owner to non-available value */
   inode->i_uid.val = -1;

   /* Set group owner to non-available value */
   inode->i_gid.val = -1;

   /* Mark inode as dirty */
   mark_inode_dirty(inode);
//   __mark_inode_dirty(inode, I_DIRTY_SYNC);

// STRONG_DEBUG
#ifdef P_LKRG_DEBUG
   p_print_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_iget_file>\n");
#endif

}

static inline void p_iput_file(struct inode *inode, kuid_t p_uid, kgid_t p_gid) {

// STRONG_DEBUG
#ifdef P_LKRG_DEBUG
   p_print_log(P_LKRG_STRONG_DBG,
          "Entering function <p_iput_file>\n");
#endif

   /* Remove S_IMMUTABLE flag for inode */
   inode->i_flags &= ~(S_IMMUTABLE);

   /* Restore original user owner value */
   inode->i_uid.val = p_uid.val;

   /* Restore original group owner value */
   inode->i_gid.val = p_gid.val;

   /* Mark inode as dirty */
   mark_inode_dirty(inode);
//   __mark_inode_dirty(inode, I_DIRTY_SYNC);

   /* Decrement reference counter */
   iput(inode);

// STRONG_DEBUG
#ifdef P_LKRG_DEBUG
   p_print_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_iput_file>\n");
#endif

}

static inline void p_iget_logs(struct inode *inode) {

#ifdef P_LKRG_DEBUG
   p_print_log(P_LKRG_STRONG_DBG,
          "Entering function <p_iget_logs>\n");
#endif

   /* Increment reference counter */
   atomic_inc(&inode->i_count);

   /* Set S_IMMUTABLE flag for inode */
   inode->i_flags |= S_APPEND;

   /* Mark inode as dirty */
   mark_inode_dirty(inode);
//   __mark_inode_dirty(inode, I_DIRTY_SYNC);

// STRONG_DEBUG
#ifdef P_LKRG_DEBUG
   p_print_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_iget_logs>\n");
#endif

}

static inline void p_iput_logs(struct inode *inode) {

// STRONG_DEBUG
#ifdef P_LKRG_DEBUG
   p_print_log(P_LKRG_STRONG_DBG,
          "Entering function <p_iput_logs>\n");
#endif

   /* Remove S_IMMUTABLE flag for inode */
   inode->i_flags &= ~(S_APPEND);

   /* Mark inode as dirty */
   mark_inode_dirty(inode);
//   __mark_inode_dirty(inode, I_DIRTY_SYNC);

   /* Decrement reference counter */
   iput(inode);

// STRONG_DEBUG
#ifdef P_LKRG_DEBUG
   p_print_log(P_LKRG_STRONG_DBG,
          "Leaving function <p_iput_logs>\n");
#endif

}

#ifdef P_LKRG_DEBUG
static inline void p_dump_inode_ops(const struct inode_operations *p_arg) {

   p_print_log(P_LKRG_DBG, "lookup => 0x%p\n",p_arg->lookup);
//   p_print_log(P_LKRG_DBG, "follow_link => 0x%p\n",p_arg->follow_link);
   p_print_log(P_LKRG_DBG, "permission => 0x%p\n",p_arg->permission);
   p_print_log(P_LKRG_DBG, "get_acl => 0x%p\n",p_arg->get_acl);
   p_print_log(P_LKRG_DBG, "readlink => 0x%p\n",p_arg->readlink);

//   p_print_log(P_LKRG_DBG, "put_link => 0x%p\n",p_arg->put_link);

   p_print_log(P_LKRG_DBG, "create => 0x%p\n",p_arg->create);
   p_print_log(P_LKRG_DBG, "link => 0x%p\n",p_arg->link);
   p_print_log(P_LKRG_DBG, "unlink => 0x%p\n",p_arg->unlink);
   p_print_log(P_LKRG_DBG, "symlink => 0x%p\n",p_arg->symlink);
   p_print_log(P_LKRG_DBG, "mkdir => 0x%p\n",p_arg->mkdir);
   p_print_log(P_LKRG_DBG, "rmdir => 0x%p\n",p_arg->rmdir);
   p_print_log(P_LKRG_DBG, "mknod => 0x%p\n",p_arg->mknod);
   p_print_log(P_LKRG_DBG, "rename => 0x%p\n",p_arg->rename);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,15,0)
   p_print_log(P_LKRG_DBG, "rename2 => 0x%p\n",p_arg->rename2);
#endif
   p_print_log(P_LKRG_DBG, "setattr => 0x%p\n",p_arg->setattr);
   p_print_log(P_LKRG_DBG, "getattr => 0x%p\n",p_arg->getattr);
   p_print_log(P_LKRG_DBG, "setxattr => 0x%p\n",p_arg->setxattr);
   p_print_log(P_LKRG_DBG, "getxattr => 0x%p\n",p_arg->getxattr);
   p_print_log(P_LKRG_DBG, "listxattr => 0x%p\n",p_arg->listxattr);
   p_print_log(P_LKRG_DBG, "removexattr => 0x%p\n",p_arg->removexattr);
   p_print_log(P_LKRG_DBG, "fiemap => 0x%p\n",p_arg->fiemap);
   p_print_log(P_LKRG_DBG, "update_time => 0x%p\n",p_arg->update_time);
   p_print_log(P_LKRG_DBG, "atomic_open => 0x%p\n",p_arg->atomic_open);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,15,0)
   p_print_log(P_LKRG_DBG, "tmpfile => 0x%p\n",p_arg->tmpfile);
   p_print_log(P_LKRG_DBG, "set_acl => 0x%p\n",p_arg->set_acl);
#endif

}

static inline void p_dump_file_ops(const struct file_operations *p_arg) {

   p_print_log(P_LKRG_DBG, "llseek => 0x%p\n",p_arg->llseek);
   p_print_log(P_LKRG_DBG, "read => 0x%p\n",p_arg->read);
   p_print_log(P_LKRG_DBG, "write => 0x%p\n",p_arg->write);
   p_print_log(P_LKRG_DBG, "read_iter => 0x%p\n",p_arg->read_iter);
   p_print_log(P_LKRG_DBG, "write_iter => 0x%p\n",p_arg->write_iter);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,11,0)
   p_print_log(P_LKRG_DBG, "iterate => 0x%p\n",p_arg->iterate);
#endif
   p_print_log(P_LKRG_DBG, "poll => 0x%p\n",p_arg->poll);
   p_print_log(P_LKRG_DBG, "unlocked_ioctl => 0x%p\n",p_arg->unlocked_ioctl);
   p_print_log(P_LKRG_DBG, "compat_ioctl => 0x%p\n",p_arg->compat_ioctl);
   p_print_log(P_LKRG_DBG, "mmap => 0x%p\n",p_arg->mmap);
   p_print_log(P_LKRG_DBG, "open => 0x%p\n",p_arg->open);
   p_print_log(P_LKRG_DBG, "flush => 0x%p\n",p_arg->flush);
   p_print_log(P_LKRG_DBG, "release => 0x%p\n",p_arg->release);
   p_print_log(P_LKRG_DBG, "fsync => 0x%p\n",p_arg->fsync);
   p_print_log(P_LKRG_DBG, "aio_fsync => 0x%p\n",p_arg->aio_fsync);
   p_print_log(P_LKRG_DBG, "fasync => 0x%p\n",p_arg->fasync);
   p_print_log(P_LKRG_DBG, "lock => 0x%p\n",p_arg->lock);
   p_print_log(P_LKRG_DBG, "sendpage => 0x%p\n",p_arg->sendpage);
   p_print_log(P_LKRG_DBG, "get_unmapped_area => 0x%p\n",p_arg->get_unmapped_area);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,11,0)
   p_print_log(P_LKRG_DBG, "check_flags => 0x%p\n",p_arg->check_flags);
#endif
   p_print_log(P_LKRG_DBG, "flock => 0x%p\n",p_arg->flock);
   p_print_log(P_LKRG_DBG, "splice_write => 0x%p\n",p_arg->splice_write);
   p_print_log(P_LKRG_DBG, "splice_read => 0x%p\n",p_arg->splice_read);
   p_print_log(P_LKRG_DBG, "setlease => 0x%p\n",p_arg->setlease);
   p_print_log(P_LKRG_DBG, "fallocate => 0x%p\n",p_arg->fallocate);
   p_print_log(P_LKRG_DBG, "show_info => 0x%p\n",p_arg->show_fdinfo);
//   p_print_log(P_LKRG_DBG, "mmap_capabilities => 0x%p\n",p_arg->mmap_capabilities);

}
#endif


struct p_protected_inode *p_rb_find_inode(struct rb_root *p_root, struct inode *p_arg);
struct p_protected_inode *p_rb_add_inode(struct rb_root *p_root, struct inode *p_arg, struct p_protected_inode *p_source);
void p_rb_del_inode(struct rb_root *p_root, struct p_protected_inode *p_source);
int p_init_rb_inodes(void);
void p_delete_rb_inodes(void);

#endif
