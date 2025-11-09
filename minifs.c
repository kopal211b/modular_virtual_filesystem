// minifs.c - Operate on formatted storage.bin
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#define BLOCK_SIZE 512
#define INODE_SIZE 128
#define FILENAME_LEN 64
#define INODE_COUNT 1024

typedef struct {
    uint32_t magic;
    uint32_t block_size;
    uint64_t total_blocks;
    uint64_t free_blocks;
    uint32_t inode_count;
    uint64_t inode_table_start;
    uint64_t data_start_block;
    uint8_t  reserved[BLOCK_SIZE - 4 -4 -8 -8 -4 -8 -8];
} Superblock;

typedef struct {
    char name[FILENAME_LEN];
    uint32_t used;
    uint32_t uid;
    uint32_t gid;
    uint32_t perms;
    uint64_t size;
    uint64_t start_block;
    uint32_t blocks_allocated;
    uint8_t  reserved[INODE_SIZE - FILENAME_LEN - 4 -4 -4 -8 -8 -4];
} Inode;

Superblock sb;
FILE *disk = NULL;
uint8_t *bitmap = NULL;
Inode *inodes = NULL;

// --- Utility Functions ---
void read_block(uint64_t block_no, void *buffer) {
    fseek(disk, block_no * BLOCK_SIZE, SEEK_SET);
    fread(buffer, 1, BLOCK_SIZE, disk);
}

void write_block(uint64_t block_no, void *buffer) {
    fseek(disk, block_no * BLOCK_SIZE, SEEK_SET);
    fwrite(buffer, 1, BLOCK_SIZE, disk);
    fflush(disk);
}

// Load metadata (superblock, bitmap, inode table)
void load_fs() {
    // Read superblock
    read_block(0, &sb);
    if (sb.magic != 0x4D494E46) {
        printf("Invalid filesystem magic. Not formatted?\n");
        exit(1);
    }

    // Load bitmap
    uint64_t bitmap_bytes = (sb.total_blocks + 7) / 8;
    uint64_t bitmap_blocks = (bitmap_bytes + BLOCK_SIZE - 1) / BLOCK_SIZE;
    bitmap = malloc(bitmap_blocks * BLOCK_SIZE);
    for (uint64_t i = 0; i < bitmap_blocks; i++)
        read_block(1 + i, bitmap + i * BLOCK_SIZE);

    // Load inode table
    uint64_t inode_table_bytes = (uint64_t)INODE_COUNT * INODE_SIZE;
    uint64_t inode_table_blocks = (inode_table_bytes + BLOCK_SIZE - 1) / BLOCK_SIZE;
    inodes = malloc(inode_table_blocks * BLOCK_SIZE);
    for (uint64_t i = 0; i < inode_table_blocks; i++)
        read_block(sb.inode_table_start + i, (uint8_t*)inodes + i * BLOCK_SIZE);

    printf("Filesystem loaded successfully.\n");
    printf("Total blocks: %llu, Free blocks: %llu\n",
           (unsigned long long)sb.total_blocks,
           (unsigned long long)sb.free_blocks);
}

void save_bitmap() {
    uint64_t bitmap_bytes = (sb.total_blocks + 7) / 8;
    uint64_t bitmap_blocks = (bitmap_bytes + BLOCK_SIZE - 1) / BLOCK_SIZE;
    for (uint64_t i = 0; i < bitmap_blocks; i++)
        write_block(1 + i, bitmap + i * BLOCK_SIZE);
}

void save_inodes() {
    uint64_t inode_table_bytes = (uint64_t)INODE_COUNT * INODE_SIZE;
    uint64_t inode_table_blocks = (inode_table_bytes + BLOCK_SIZE - 1) / BLOCK_SIZE;
    for (uint64_t i = 0; i < inode_table_blocks; i++)
        write_block(sb.inode_table_start + i, (uint8_t*)inodes + i * BLOCK_SIZE);
}

// --- Bitmap Operations ---
int find_free_block() {
    for (uint64_t i = sb.data_start_block; i < sb.total_blocks; i++) {
        uint64_t byte = i / 8, bit = i % 8;
        if (!(bitmap[byte] & (1 << bit))) {
            bitmap[byte] |= (1 << bit);
            sb.free_blocks--;
            return i;
        }
    }
    return -1;
}

void free_block(int block) {
    uint64_t byte = block / 8, bit = block % 8;
    bitmap[byte] &= ~(1 << bit);
    sb.free_blocks++;
}

// --- FS Commands ---
void create_file() {
    char name[FILENAME_LEN], content[BLOCK_SIZE];
    printf("Enter file name: ");
    scanf("%s", name);
    printf("Enter content: ");
    scanf(" %[^\n]", content);

    // find free inode
    int idx = -1;
    for (int i = 0; i < INODE_COUNT; i++) {
        if (!inodes[i].used) { idx = i; break; }
    }
    if (idx == -1) { printf("No free inode.\n"); return; }

    int b = find_free_block();
    if (b == -1) { printf("No free block.\n"); return; }

    // write content
    write_block(b, content);

    // fill inode
    Inode *node = &inodes[idx];
    memset(node, 0, sizeof(Inode));
    strncpy(node->name, name, FILENAME_LEN-1);
    node->used = 1;
    node->uid = 0;
    node->gid = 0;
    node->perms = 0644;
    node->size = strlen(content);
    node->start_block = b;
    node->blocks_allocated = 1;

    save_bitmap();
    save_inodes();

    printf("File '%s' created at block %d.\n", name, b);
}

void list_files() {
    printf("Files in FS:\n");
    for (int i = 0; i < INODE_COUNT; i++) {
        if (inodes[i].used)
            printf("%s (size=%llu bytes, block=%llu)\n",
                   inodes[i].name,
                   (unsigned long long)inodes[i].size,
                   (unsigned long long)inodes[i].start_block);
    }
}

void read_file() {
    char name[FILENAME_LEN];
    printf("Enter file name: ");
    scanf("%s", name);
    for (int i = 0; i < INODE_COUNT; i++) {
        if (inodes[i].used && strcmp(inodes[i].name, name) == 0) {
            char buf[BLOCK_SIZE + 1];
            read_block(inodes[i].start_block, buf);
            buf[inodes[i].size] = '\0';
            printf("Content: %s\n", buf);
            return;
        }
    }
    printf("File not found.\n");
}

void delete_file() {
    char name[FILENAME_LEN];
    printf("Enter file name: ");
    scanf("%s", name);
    for (int i = 0; i < INODE_COUNT; i++) {
        if (inodes[i].used && strcmp(inodes[i].name, name) == 0) {
            free_block(inodes[i].start_block);
            inodes[i].used = 0;  // mark as deleted but keep metadata
            save_bitmap();
            save_inodes();
            printf("File deleted (marked as recoverable).\n");
            return;
        }
    }
    printf("File not found.\n");
}

void dump_block(uint64_t block_no) {
    uint8_t buf[BLOCK_SIZE];
    read_block(block_no, buf);

    printf("--- Block %llu ---\n", (unsigned long long)block_no);
    for (int i = 0; i < BLOCK_SIZE; i += 16) {
        printf("%04x  ", i);
        for (int j = 0; j < 16; j++) {
            if (i + j < BLOCK_SIZE)
                printf("%02x ", buf[i + j]);
            else
                printf("   ");
        }
        printf(" | ");
        for (int j = 0; j < 16; j++) {
            if (i + j < BLOCK_SIZE) {
                unsigned char c = buf[i + j];
                printf("%c", (c >= 32 && c <= 126) ? c : '.');
            }
        }
        printf("\n");
    }
}

void dump_blocks_for_file() {
    char name[FILENAME_LEN];
    printf("Enter file name: ");
    scanf("%s", name);

    for (int i = 0; i < INODE_COUNT; i++) {
        if (inodes[i].used && strcmp(inodes[i].name, name) == 0) {
            printf("\nDumping blocks for file '%s':\n", name);
            printf("Start block: %llu, Blocks allocated: %u\n\n",
                   (unsigned long long)inodes[i].start_block,
                   inodes[i].blocks_allocated);

            for (uint32_t b = 0; b < inodes[i].blocks_allocated; b++)
                dump_block(inodes[i].start_block + b);

            return;
        }
    }
    printf("File not found.\n");
}

void recover_file() {
    int found = 0;
    char choice[FILENAME_LEN];

    printf("Scanning for deleted files...\n");

    // show deleted files (used==0 but name not empty)
    for (int i = 0; i < INODE_COUNT; i++) {
        if (!inodes[i].used && strlen(inodes[i].name) > 0) {
            printf("Found deleted file: %s (size=%llu bytes, block=%llu)\n",
                   inodes[i].name,
                   (unsigned long long)inodes[i].size,
                   (unsigned long long)inodes[i].start_block);
            found = 1;
        }
    }

    if (!found) {
        printf("No deleted files found.\n");
        return;
    }

    printf("Enter file name to recover: ");
    scanf("%s", choice);

    for (int i = 0; i < INODE_COUNT; i++) {
        if (!inodes[i].used && strcmp(inodes[i].name, choice) == 0) {
            uint64_t blk = inodes[i].start_block;
            uint64_t byte = blk / 8, bit = blk % 8;

            // if block is still free (not overwritten)
            if (!(bitmap[byte] & (1 << bit))) {
                bitmap[byte] |= (1 << bit);  // mark block used again
                sb.free_blocks--;
                inodes[i].used = 1;
                save_bitmap();
                save_inodes();
                printf("File '%s' successfully recovered!\n", choice);
            } else {
                printf("Cannot recover '%s': data block reused.\n", choice);
            }
            return;
        }
    }

    printf("No matching deleted file found.\n");
}

// --- main ---
int main() {
    disk = fopen("storage.bin", "r+b");
    if (!disk) {
        printf("storage.bin not found. Run formatter first.\n");
        return 1;
    }

    load_fs();

    int choice;
    while (1) {
    printf("\nMiniFS Menu:\n");
    printf("1. Create File\n");
    printf("2. List Files\n");
    printf("3. Read File\n");
    printf("4. Delete File\n");
    printf("5. Recover File\n");
    printf("6. Dump Specific Block\n");
    printf("7. Dump Blocks of a File\n");
    printf("8. Exit\n");
    printf("Choice: ");
    scanf("%d", &choice);

    switch (choice) {
        case 1: create_file(); break;
        case 2: list_files(); break;
        case 3: read_file(); break;
        case 4: delete_file(); break;
        case 5: recover_file(); break;
        case 6: {
            uint64_t blk;
            printf("Enter block number: ");
            scanf("%llu", &blk);
            dump_block(blk);
            break;
        }
        case 7: dump_blocks_for_file(); break;
        case 8:
            fclose(disk); free(bitmap); free(inodes);
            exit(0);
        default: printf("Invalid choice.\n");
    }
}
}

