// format_storage_safe.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#define BLOCK_SIZE 512
#define INODE_SIZE 128
#define INODE_COUNT 1024
#define FILENAME_LEN 64

typedef struct {
    uint32_t magic;           // filesystem magic
    uint32_t block_size;      // 512
    uint64_t total_blocks;    // total blocks in image
    uint64_t free_blocks;     // free blocks left (after metadata)
    uint32_t inode_count;     // number of inodes
    uint64_t inode_table_start;// start block of inode table
    uint64_t data_start_block; // first data block
    uint8_t  reserved[BLOCK_SIZE - 4 -4 -8 -8 -4 -8 -8]; // pad to 512 bytes
} Superblock;

typedef struct {
    char name[FILENAME_LEN];
    uint32_t used;         // 0 = free, 1 = used
    uint32_t uid;
    uint32_t gid;
    uint32_t perms;        // simple permission bits
    uint64_t size;         // file size in bytes
    uint64_t start_block;  // starting data block (contiguous allocation for simplicity)
    uint32_t blocks_allocated;
    uint8_t  reserved[INODE_SIZE - FILENAME_LEN - 4 -4 -4 -8 -8 -4];
} Inode;

static off_t get_file_size(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    return st.st_size;
}

int main(int argc, char **argv) {
    const char *img = "storage.bin";
    if (argc >= 2) img = argv[1];

    off_t filesize = get_file_size(img);
    if (filesize <= 0) {
        fprintf(stderr, "Cannot stat %s or file empty\n", img);
        return 1;
    }

    uint64_t total_blocks = (uint64_t)filesize / BLOCK_SIZE;
    if (total_blocks < 100) {
        fprintf(stderr, "Image too small: need at least ~100 blocks\n");
        return 1;
    }

    // Compute bitmap size in bytes and blocks
    uint64_t bitmap_bytes = (total_blocks + 7) / 8;
    uint64_t bitmap_blocks = (bitmap_bytes + BLOCK_SIZE - 1) / BLOCK_SIZE;

    // Compute inode table size in bytes and blocks
    uint64_t inode_table_bytes = (uint64_t)INODE_COUNT * INODE_SIZE;
    uint64_t inode_table_blocks = (inode_table_bytes + BLOCK_SIZE - 1) / BLOCK_SIZE;

    // layout: block 0 = superblock
    uint64_t superblock_blocks = 1;
    uint64_t bitmap_start = superblock_blocks;
    uint64_t inode_table_start = bitmap_start + bitmap_blocks;
    uint64_t data_start = inode_table_start + inode_table_blocks;

    if (data_start >= total_blocks) {
        fprintf(stderr, "Not enough space for metadata. total_blocks=%llu, needed=%llu\n",
                (unsigned long long)total_blocks, (unsigned long long)data_start);
        return 1;
    }

    int fd = open(img, O_RDWR);
    if (fd < 0) { perror("open"); return 1; }

    // --- write superblock ---
    Superblock sb;
    memset(&sb, 0, sizeof(sb));
    sb.magic = 0x4D494E46; // 'MINF'
    sb.block_size = BLOCK_SIZE;
    sb.total_blocks = total_blocks;
    sb.free_blocks = total_blocks - (superblock_blocks + bitmap_blocks + inode_table_blocks);
    sb.inode_count = INODE_COUNT;
    sb.inode_table_start = inode_table_start;
    sb.data_start_block = data_start;

    if (lseek(fd, 0, SEEK_SET) == -1) { perror("lseek sb"); close(fd); return 1; }
    if (write(fd, &sb, sizeof(sb)) != (ssize_t)sizeof(sb)) { perror("write sb"); close(fd); return 1; }

    // pad the rest of superblock block
    if (BLOCK_SIZE > sizeof(sb)) {
        uint8_t zero[BLOCK_SIZE] = {0};
        if (write(fd, zero, BLOCK_SIZE - sizeof(sb)) != (ssize_t)(BLOCK_SIZE - sizeof(sb))) { perror("write pad"); close(fd); return 1; }
    }

    // --- write bitmap block by block ---
    uint8_t bitmap_block[BLOCK_SIZE];
    for (uint64_t b = 0; b < bitmap_blocks; b++) {
        memset(bitmap_block, 0, BLOCK_SIZE);
        for (uint64_t i = 0; i < BLOCK_SIZE*8; i++) {
            uint64_t block_no = b*BLOCK_SIZE*8 + i;
            if (block_no < data_start) {
                bitmap_block[i/8] |= (1 << (i % 8));
            }
        }
        if (lseek(fd, (off_t)(bitmap_start + b) * BLOCK_SIZE, SEEK_SET) == -1) { perror("lseek bitmap"); close(fd); return 1; }
        if (write(fd, bitmap_block, BLOCK_SIZE) != BLOCK_SIZE) { perror("write bitmap"); close(fd); return 1; }
    }

    // --- write inode table block by block ---
    uint8_t inode_block[BLOCK_SIZE];
    memset(inode_block, 0, BLOCK_SIZE);
    Inode root = {0};
    strncpy(root.name, "/", FILENAME_LEN-1);
    root.used = 1;
    root.uid = 0;
    root.gid = 0;
    root.perms = 0755;
    root.size = 0;
    root.start_block = 0;
    root.blocks_allocated = 0;

    for (uint64_t b = 0; b < inode_table_blocks; b++) {
        memset(inode_block, 0, BLOCK_SIZE);
        uint64_t start_inode = b * (BLOCK_SIZE / INODE_SIZE);
        for (uint64_t i = 0; i < BLOCK_SIZE / INODE_SIZE && (start_inode + i) < INODE_COUNT; i++) {
            Inode *inode_ptr = ((Inode*)inode_block) + i;
            if (start_inode + i == 0) *inode_ptr = root;
        }
        if (lseek(fd, (off_t)(inode_table_start + b) * BLOCK_SIZE, SEEK_SET) == -1) { perror("lseek inode"); close(fd); return 1; }
        if (write(fd, inode_block, BLOCK_SIZE) != BLOCK_SIZE) { perror("write inode"); close(fd); return 1; }
    }

    fsync(fd);
    close(fd);

    printf("Formatted image: %s\n", img);
    printf("BLOCK_SIZE=%d TOTAL_BLOCKS=%llu\n", BLOCK_SIZE, (unsigned long long)total_blocks);
    printf("Superblock blocks=1, bitmap blocks=%llu, inode table blocks=%llu\n",
           (unsigned long long)bitmap_blocks, (unsigned long long)inode_table_blocks);
    printf("Data starts at block %llu\n", (unsigned long long)data_start);
    printf("Free blocks = %llu\n", (unsigned long long)sb.free_blocks);

    return 0;
}
