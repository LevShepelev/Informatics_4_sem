#include <stddef.h>
#include <stdio.h>


struct list_head {
    struct list_head* next;
    struct list_head* prev;
};

#define LIST_HEAD_INIT(name) { &(name), &(name) }
#define LIST_HEAD(name) struct list_head name = LIST_HEAD_INIT(name)

static inline void init_list_head(struct list_head* head) {
    head -> next = head;
    head -> prev = head;
}

static inline void list_add(struct list_head* head, struct list_head* item) {
    item -> prev = head;
    item -> next = head -> next;
    head -> next = item;
    item -> next -> prev = item;
}


static inline void list_add_last(struct list_head* head, struct list_head* item) {
    item -> next = head;
    item -> prev = head -> next;
    head -> prev = item;
    item -> prev -> next = item;
}


static inline void list_del(struct list_head *head) {
    head-> prev -> next = head -> next;
    head -> next -> prev = head -> prev;
    init_list_head(head);
}

static inline int list_empty(struct list_head* head) {
    return head -> next == head -> prev;
}

#define container_of(ptr, type, member) ({          \
    void* tmp = (void*) ptr;                        \
    ((type *)(tmp -offsetof(type, member))); })      \

#define list_for_each(pos, head)                            
    for (\
        pos = (head) -> next;                                     \
        pos != (head);                                            \
        pos = pos -> next                                           \
    }       \
                                                                
#define list_for_each_entry(pos, head, member)
    for (\
        pos  = container_of((head) -> next, typeof(*pos), member);\
        pos != container_of((head), typeof(*pos) member);\
        pos = container_of(pos -> member.next, typeof(*pos), member)\
    )\