// SPDX-License-Identifier: BSD-3-Clause
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "osmem.h"
#include "block_meta.h"

#define MMAP_THRESHOLD 131072  // 128 * 1024
#define PADDING 8
#define BLOCKMETA 32 // sizeof(struct block_meta)

struct block_meta *heap_start;

void *os_malloc(size_t size)
{
	struct block_meta *best_fit_block = NULL;
	struct block_meta *current = NULL;
	struct block_meta *remaining_block = NULL;
	struct block_meta *block = NULL;
	struct block_meta *last_block = NULL;
	size_t remaining_size;
	size_t total_size = size + BLOCKMETA;

	total_size = (total_size + PADDING - 1) & ~(PADDING - 1);

	if (!size)
		return NULL;

	if (total_size <= MMAP_THRESHOLD) {
		// Caz lista de blocuri cu brk()

		// Verific daca a fost prealocata o zona de memorie intial
		if (!heap_start) {
			heap_start = sbrk(MMAP_THRESHOLD);
			if (heap_start == (void *)-1)
				return NULL;

			heap_start->status = STATUS_FREE;
			heap_start->size = MMAP_THRESHOLD - BLOCKMETA;
			heap_start->prev = NULL;
			heap_start->next = NULL;
		}

		// Caut cel mai apropiat block liber in care pot aloca memorie
		current = heap_start;
		best_fit_block = NULL;

		while (current) {
			if (current->status == STATUS_FREE &&
				current->size >= total_size - BLOCKMETA) {
				if (!best_fit_block)
					best_fit_block = current;
				else if (current->size < best_fit_block->size)
					best_fit_block = current;
			}

			current = current->next;
		}

		if (best_fit_block) {
			// In cazul in care am gasit un bloc, verific daca exista loc pentru inca un block STATUS_FREE
			if (best_fit_block->size > total_size) {
				remaining_block = (struct block_meta *)((void *)best_fit_block + total_size);
				remaining_block->status = STATUS_FREE;
				remaining_block->size = best_fit_block->size - total_size;

				remaining_block->prev = best_fit_block;
				remaining_block->next = best_fit_block->next;
				if (best_fit_block->next)
					best_fit_block->next->prev = remaining_block;
				best_fit_block->next = remaining_block;

				best_fit_block->size = total_size - BLOCKMETA;

			    // Daca dupa blockul STATUS_FREE exista minim un bloc liber,
			    // trebuie comprimate intr-un singur block STATUS_FREE
				if (remaining_block->next && remaining_block->next->status == STATUS_FREE) {
					remaining_block->size += remaining_block->next->size + BLOCKMETA;
					remaining_block->next = remaining_block->next->next;
					if (remaining_block->next)
						remaining_block->next->prev = remaining_block;
				}
			}

			best_fit_block->status = STATUS_ALLOC;

			return (best_fit_block + 1);
		}

		// Daca nu pot utiliza resursele actuale, extind zona de memorie si actualizez ultimul block
		last_block = heap_start;
		while (last_block->next)
			last_block = last_block->next;

		if (last_block->size < total_size - BLOCKMETA && last_block->status == STATUS_FREE) {
			remaining_size = total_size - BLOCKMETA - last_block->size;
			block = sbrk(remaining_size);
			DIE(!block, "block not allocated");
			last_block->size = total_size - BLOCKMETA;
			last_block->status = STATUS_ALLOC;
			return (last_block + 1);
		}

		block = sbrk(total_size);
		DIE(!block, "block not allocated");

		block->status = STATUS_ALLOC;
		block->size = total_size - BLOCKMETA;

		last_block->next = block;
		block->prev = last_block;
		block->next = NULL;

		return (block + 1);
	}

	// Caz zona mapata, nu este necesara folosirea listelor datorita mmap
	block = mmap(0, total_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	DIE(!block, "block not mapped");

	block->status = STATUS_MAPPED;
	block->size = total_size - BLOCKMETA;
	block->prev = NULL;
	block->next = NULL;

	return (block + 1);
}

void os_free(void *ptr)
{
	if (!ptr)
		return;

	struct block_meta *block = (struct block_meta *)(ptr - BLOCKMETA);

	if (block->status == STATUS_MAPPED) {
		if (block->prev)
			block->prev->next = block->next;
		if (block->next)
			block->next->prev = block->prev;

		munmap(block, block->size + BLOCKMETA);
	} else {
		// Daca blockul eliberat are vecini STATUS_FREE, trebuie facut merge
		block->status = STATUS_FREE;

		if (block->prev && block->prev->status == STATUS_FREE) {
			block->prev->next = block->next;
			block->prev->size += block->size + BLOCKMETA;
			block = block->prev;
			if (block->next)
				block->next->prev = block;
		}

		if (block->next && block->next->status == STATUS_FREE) {
			block->size += block->next->size + BLOCKMETA;
			block->next = block->next->next;
			if (block->next)
				block->next->prev = block;
		}
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	struct block_meta *best_fit_block = NULL;
	struct block_meta *current = NULL;
	struct block_meta *remaining_block = NULL;
	struct block_meta *block = NULL;
	struct block_meta *last_block = NULL;
	size_t remaining_size;
	// aloc nmmeb elemente de dimensiune size
	size_t total_size = nmemb * size + BLOCKMETA;

	if (!nmemb || !size)
		return NULL;

	total_size = (total_size + PADDING - 1) & ~(PADDING - 1);

	// zonele cu dimensini mai mici decat pagesize sunt alocate folosind liste si brk()
	if (total_size <= (size_t)getpagesize()) {
		// Verific daca a fost prealocata o zona de memorie intial
		if (!heap_start) {
			heap_start = sbrk(MMAP_THRESHOLD);

			DIE(heap_start == (void *)-1, "heap_start not allocated");

			heap_start->status = STATUS_FREE;
			heap_start->size = MMAP_THRESHOLD - BLOCKMETA;
			heap_start->prev = NULL;
			heap_start->next = NULL;
		}

		// Caut cel mai apropiat block liber in care pot aloca memorie
		current = heap_start;
		best_fit_block = NULL;

		while (current) {
			if (current->status == STATUS_FREE &&
				current->size >= total_size - BLOCKMETA) {
				if (!best_fit_block)
					best_fit_block = current;
				else if (current->size < best_fit_block->size)
					best_fit_block = current;
			}
			current = current->next;
		}

		if (best_fit_block) {
			// In cazul in care am gasit un bloc, verific daca exista loc pentru inca un block STATUS_FREE
			if (best_fit_block->size > total_size) {
				remaining_block = (struct block_meta *)((void *)best_fit_block + total_size);
				remaining_block->status = STATUS_FREE;
				remaining_block->size = best_fit_block->size - total_size;

				remaining_block->prev = best_fit_block;
				remaining_block->next = best_fit_block->next;
				if (best_fit_block->next)
					best_fit_block->next->prev = remaining_block;
				best_fit_block->next = remaining_block;
				best_fit_block->size = total_size - BLOCKMETA;

				// Daca dupa blockul STATUS_FREE exista minim un bloc liber,
			    // trebuie comprimate intr-un singur block STATUS_FREE
				if (remaining_block->next &&
					remaining_block->next->status == STATUS_FREE) {
					remaining_block->size +=
						remaining_block->next->size + BLOCKMETA;
					remaining_block->next = remaining_block->next->next;
					if (remaining_block->next)
						remaining_block->next->prev = remaining_block;
				}
			}

			best_fit_block->status = STATUS_ALLOC;
			memset(best_fit_block + 1, 0, best_fit_block->size);

			return (best_fit_block + 1);
		}

		// Daca nu pot utiliza resursele actuale, extind zona de memorie si actualizez ultimul block
		block = NULL;
		last_block = heap_start;

		while (last_block->next)
			last_block = last_block->next;

		if (last_block->size < total_size - BLOCKMETA &&
			last_block->status == STATUS_FREE) {
			remaining_size = total_size - BLOCKMETA - last_block->size;
			block = sbrk(remaining_size);

			DIE(block == (void *)-1, "block not allocated");

			last_block->size = total_size - BLOCKMETA;
			last_block->status = STATUS_ALLOC;
			memset(last_block + 1, 0, last_block->size);

			return (last_block + 1);
		}

		block = sbrk(total_size);
		DIE(block == (void *)-1, "block not allocated");

		block->status = STATUS_ALLOC;
		block->size = total_size - BLOCKMETA;

		last_block->next = block;
		block->prev = last_block;
		block->next = NULL;
		memset(block + 1, 0, block->size);

		return (block + 1);
	}

	// Caz zona mapata, nu este necesara folosirea listelor datorita mmap
	block = mmap(0, total_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	DIE(!block, "block not mapped");

	block->status = STATUS_MAPPED;
	block->size = total_size - BLOCKMETA;
	block->prev = NULL;
	block->next = NULL;
	memset(block + 1, 0, block->size);

	return (block + 1);
}

void *os_realloc(void *ptr, size_t size)
{
	if (!ptr)
		return os_malloc(size);

	if (!size) {
		os_free(ptr);
		return NULL;
	}

	struct block_meta *block = (struct block_meta *)ptr - 1;
	struct block_meta *new_block = NULL;
	struct block_meta *remaining_block = NULL;
	void *new_ptr = NULL;
	size_t total_size = size + BLOCKMETA;

	size = (size + PADDING - 1) & ~(PADDING - 1);
	total_size = (total_size + PADDING - 1) & ~(PADDING - 1);

	if (block->status == STATUS_FREE)
		return NULL;

	if (block->status == STATUS_MAPPED) {
		if (size > MMAP_THRESHOLD) {
			// mapam noua dimensiune de memorie si dezalocam zona veche
			void *new_ptr = mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

			DIE(!new_ptr, "new_ptr not mapped");

			new_block = (struct block_meta *)new_ptr;
			new_block->size = size;
			new_block->status = STATUS_MAPPED;
			if (size >= block->size)
				memcpy(new_block + 1, ptr, block->size);
			else
				memcpy(new_block + 1, ptr, size);

			munmap(ptr - BLOCKMETA,
				   block->size + BLOCKMETA);
			return new_block + 1;
		}

		// nu se folosesc liste, deoarece zona este mapata
		new_ptr = os_malloc(size);

		if (!new_ptr)
			return NULL;

		// mutam informatia in noua zona
		if (size >= block->size)
			memcpy(new_ptr, ptr, block->size);
		else
			memcpy(new_ptr, ptr, size);

		os_free(ptr);

		return new_ptr;
	}

	// zona este alocata in lista de blockuri
	if (block->size >= size) {
		// verific daca exista loc pentru inca un block STATUS_FREE
		if (block->size > total_size) {
			remaining_block = (struct block_meta *)((void *)block + total_size);
			remaining_block->status = STATUS_FREE;
			remaining_block->size = block->size - total_size;

			remaining_block->prev = block;
			remaining_block->next = block->next;
			if (block->next)
				block->next->prev = remaining_block;
			block->next = remaining_block;

			block->size = size;

			// daca vecinii noului block STATUS_FREE sunt liberi, trebuie facut merge
			if (remaining_block->next && remaining_block->next->status == STATUS_FREE) {
				remaining_block->size +=
					remaining_block->next->size + BLOCKMETA;
				remaining_block->next = remaining_block->next->next;
				if (remaining_block->next)
					remaining_block->next->prev = remaining_block;
			}
		}

		return block + 1;
	}

	// prelungim zona de memorie
	if (!block->next) {
		new_ptr = sbrk(size - block->size);

		DIE(!new_ptr, "new_ptr not allocated");

		block->size = size;

		return ptr;
	}

	// daca urmatorul block este de tip STATUS_FREE si are o dimensiune suficienta,
	//putem majora dimensiunea blockului target
	if (block->next->status == STATUS_FREE &&
		block->next->size + BLOCKMETA + block->size >= size) {
		block->size += block->next->size + BLOCKMETA;
		block->next = block->next->next;

		if (block->next)
			block->next->prev = block;

		// caz in care mai ramane spatiu dupa ce am reallocat blockul target,
		// zona este marcata STATUS_FREE
		if (block->size - size > BLOCKMETA) {
			remaining_block = (struct block_meta *)((void *)block + total_size);
			remaining_block->status = STATUS_FREE;
			remaining_block->size = block->size - total_size;
			remaining_block->prev = block;
			remaining_block->next = block->next;
			if (block->next)
				block->next->prev = remaining_block;
			block->next = remaining_block;
			block->size = size;
		}

		return (block + 1);
	}

	new_ptr = os_malloc(size);

	DIE(!new_ptr, "new_ptr not allocated");

	if (size >= block->size)
		memcpy(new_ptr, ptr, block->size);
	else
		memcpy(new_ptr, ptr, size);

	os_free(ptr);

	return new_ptr;
}
