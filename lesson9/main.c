#include "list.h"

struct my_struct{
    char name[1024];
    int wtf;
    struct list_head lst;
};

LIST_HEAD(my_list);

int main() {
    struct my_struct m1 = {.name = "m1 name"};
    struct my_struct m2 = {.name = "m2 name"};
    struct list_head *m1_head;
    struct my_struct *m1_ptr;
    struct my_struct *i_entry;
    struct list_head *i_lst;

    init_list_head(&m1.lst);
    init_list_head(&m2.lst);

    list_add(&my_list, &m1.lst);
    list_add_last(&my_list, &m2.lst);

    //m1_head = m2.lst.prev;
    //m1_ptr = container_of(m1_head, my_struct, lst);

    printf("%s\n\n", m1_ptr -> name);

    list_for_each(i_lst, my_list)
        printf("%s\n", container_of(i_lst, struct my_struct, lst) -> name);

    list_for_each_entry(i, &my_list, lst)
        printf("%s\n", i_entry -> name);
    
}