/* This file is part of Netsukuku
 * (c) Copyright 2005 Andrea Lo Pumo aka AlpT <alpt@freaknet.org>
 *
 * This source code is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published 
 * by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This source code is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * Please refer to the GNU Public License for more details.
 *
 * You should have received a copy of the GNU Public License along with
 * this source code; if not, write to:
 * Free Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * --
 *
 * llist.c: Various functions to handle (doubled) linked lists
 * 
 * Why did I used macros for all these functions?
 * Well, I just love the blue-smurf-like syntax highlighting of Vim ^_-
 *
 * Moreover using `typeof' and other nice tricks each macro can recognize the
 * size of the arguments, in this way we can have functions like `list_copy',
 * `list_init'.
 * Finally, performance is optimised. I don't trust gcc and its -O2, (and they
 * don't trust me).
 */

#ifndef LLIST_C
#define LLIST_C

/*
 * This struct is used as a header to handle all the linked list struct.
 * The only limitation is to put _EXACTLY_ 
 * 	struct bla_bla *next;
 * 	struct bla_bla *prev; 
 * at the beginning.
 * You can also use the LLIST_HDR() macro.
 */

#define LLIST_HDR(_struct)	_struct *next, *prev

struct linked_list
{
	LLIST_HDR	(struct linked_list);
}linked_list;
typedef struct linked_list l_list;

#define is_list_zero(list)						\
({									\
 	int _iz, _rz=1;							\
	char *_a=(char *)(list);					\
	for(_iz=0; _iz<sizeof(typeof(*(list))); _iz++, _a++)		\
		if(*_a)	{						\
			_rz=0;						\
			break;						\
		}							\
	_rz;								\
})

/*
 * list_copy
 *
 * It copies just the contents of `new' in `list' without overwriting the
 * ->prev and ->next pointers.
 */
#define list_copy(list, new)						\
do{									\
	l_list _oc, *_lc=(l_list *)(list);				\
	if((new)) {							\
		_oc.prev=_lc->prev;					\
		_oc.next=_lc->next;					\
		memcpy((list), (new), sizeof(typeof(*(new))));		\
		_lc->prev=_oc.prev;					\
		_lc->next=_oc.next;					\
	}								\
} while(0)

/*
 * list_dup
 *
 * the strdup equivalent of a single llist
 */
#define list_dup(list)							\
({									\
	l_list *_dd;							\
	_dd=xmalloc(sizeof(typeof(*(list))));				\
	memset(_dd, 0, sizeof(typeof(*(list))));			\
	list_copy(_dd, (list));						\
	(typeof((list)))_dd;						\
})

/*
 * list_init
 *
 * If `new' is 0, it stores in `list' a pointer to a newly mallocated 
 * and zeroed struct.
 * Its type is the same of `list'.
 * If `new' is non zero, then `list' is simply set to `new'.
 * The ->prev and ->next pointers are always set to zero.
 */
#define list_init(list, new)						\
do {									\
	l_list *_li;							\
	if((new))							\
		(list)=(new);						\
	else								\
		(list)=(typeof (list))xmalloc(sizeof(typeof(*(list))));	\
	_li=(l_list *)(list);						\
	_li->prev=0; 							\
	_li->next=0;							\
	if(!(new))							\
		memset((list), 0, sizeof(typeof(*(list)))); 		\
} while (0)

/*
 * list_last
 *
 * It returns the last element of the `list' llist
 */
#define list_last(list)							\
({									\
	 l_list *_il=(l_list *)(list);					\
	 for(; _il && _il->next; _il=(l_list *)_il->next);		\
 	 (typeof((list)))_il;						\
})

/*
 * list_head
 *
 * Returns the head of the linked list.
 */
#define list_head(tail)							\
({									\
	 l_list *_ih=(l_list *)(list);					\
	 for(; _ih && _ih->prev; _ih=(l_list *)_ih->prev);		\
 	 (typeof((list)))_ih;						\
})

/*
 * list_append
 *
 * It appends the `_new' struct at the end of the `_head' llist.
 * If `_tail' is not 0, then it is considered as the end of the llist and the
 * `_head' argument isn't required.
 * If `_tail' is 0, the end will be reached by traversing the entire llist,
 * starting from `_head'.
 * If both `_tail' and `_head' are 0, `new->next' and `new->prev' will be set
 * to 0.
 * The new tail is always returned.
 * Example: tail=list_append(0, tail, new);
 * 	    or
 * 	    list_append(head, 0, new);
 */
#define list_append(_head, _tail, _new)					\
({									\
	l_list *_tt, *_na;						\
	_tt=(_tail) ? (l_list *)(_tail) : (l_list *)list_last((_head)); \
	_na=(l_list *)(_new);						\
 	if(_na != _tt) {						\
 		if(_tt)							\
			_tt->next=_na;					\
 		if(_na) {						\
			_na->prev=_tt; 					\
			_na->next=0;					\
		}							\
	}								\
	_new;								\
})

/*
 * list_add
 *
 * It adds the `_new' struct at the start of the `_head' llist.
 * The new head of the llist is returned.
 * 
 * Example: 
 * 		head=list_add(head, new);
 */
#define list_add(_head, _new)						\
({									\
 	l_list *_hd, *_nd;						\
 	_hd=(l_list *)(_head);						\
 	_nd=(l_list *)(_new);						\
 	if(_hd != _nd) {						\
		_nd->next=_hd;						\
		_nd->prev=0;						\
 		if(_hd)							\
			_hd->prev=_nd;					\
	}								\
	(typeof((_head)))_nd;						\
})
 
/*
 * list_join: 
 * before list_join(list):
 * 	... <-> A <-> list <-> C <-> ...
 * after:
 * 	... <-> A <-> C <-> ...
 * Note that `list' is not freed!
 * It returns the head of the list, so call it in this way:
 * 	head=list_join(head, list);
 */
#define list_join(head, list)						\
({									\
	l_list *_lj=(l_list *)(list), *_hj=(l_list *)(head), *_ret;	\
	if(_lj->next)							\
		_lj->next->prev=_lj->prev;				\
	if(_lj->prev)							\
		_lj->prev->next=_lj->next;				\
	_ret = _lj == _hj ? _lj->next : _hj;				\
	(typeof((head)))_ret;						\
})

#define list_free(list)							\
do {									\
	memset((list), 0, sizeof(typeof(*(list)))); 			\
	xfree((list));							\
} while(0)

/* 
 * list_del
 * 
 * It's the same of list_join() but it frees the `list'.
 * It returns the new head of the linked list, so it must be called in
 * this way: head=list_del(head, list); 
 */
#define list_del(head, list)						\
({									\
	l_list *_lid=(l_list *)(list), *_hed=(l_list *)(head);	 	\
 									\
 	_hed=(l_list *)list_join((head), _lid);				\
        list_free(_lid); 						\
	(typeof((head)))_hed;						\
})

/*
 * list_ins
 *
 * It inserts the `new' struct between the `list' and `list'->next 
 * structs.
 */
#define list_ins(list, new)						\
do {									\
	l_list *_lin=(l_list *)(list), *_n=(l_list *)(new);		\
	if(_lin->next)							\
		_lin->next->prev=_n;					\
	_n->next=_lin->next;						\
	_lin->next=_n;							\
	_n->prev=_lin;							\
} while (0)
	
/* 
 * list_substitute
 *
 * It removes from the llist the `old_list' struct and inserts in its
 * position the `new_list' struct
 * Note that `old_list' isn't freed, it is just unlinked from the llist.
 */
#define list_substitute(old_list, new_list)				\
do{									\
	l_list *_ns, *_os;						\
	_ns=(l_list *)(new_list);					\
	_os=(l_list *)(old_list);					\
	if(_os->next != _ns)						\
		_ns->next=_os->next;					\
	if(_os->prev != _ns)						\
		_ns->prev=_os->prev;					\
	if(_ns->next)							\
		_ns->next->prev=_ns;					\
	if(_ns->prev)							\
		_ns->prev->next=_ns;					\
}while(0)

/*
 * list_swap
 *
 * Before:	H -> Y <-> [A] <-> I <-> [B] <-> P <-> T
 * list_swap(A, B);
 * After:	H -> Y <-> [B] <-> I <-> [A] <-> P <-> T	
 */
#define list_swap(a, b)							\
do{									\
	l_list _ltmp, *_aa, *_bb;					\
	_aa=(l_list *)(a);						\
	_bb=(l_list *)(b);						\
	if(_aa->next == _bb) {						\
		list_substitute(_aa, _bb);				\
		list_ins(_bb, _aa);					\
	} else if(_aa->prev == _bb) {					\
		list_substitute(_bb, _aa);				\
		list_ins(_aa, _bb);					\
	} else {							\
		_ltmp.next=(l_list *)_bb->next;				\
		_ltmp.prev=(l_list *)_bb->prev;				\
		list_substitute(_aa, _bb);				\
		list_substitute(&_ltmp, _aa);				\
	}								\
}while(0)

/*
 * list_moveback
 *
 * It swaps `list' with its previous struct
 */
#define list_moveback(list)						\
do{									\
	l_list *_lm=(l_list *)(list);					\
	if(_lm->prev)							\
		list_swap(_lm->prev, _lm);				\
}while(0)

/*
 * list_movefwd
 *
 * It swaps `list' with its next struct
 */
#define list_movefwd(list)						\
do{									\
	l_list *_lmf=(l_list *)(list);					\
	if(_lmf->next)							\
		list_swap(_lmf->next, _lmf);				\
}while(0)
 
/* 
 * list_moveontop
 *
 * `_list' must be already present in the `_head' llist, otherwise this
 * function is just equal to list_add().
 * 
 * list_moveontop() moves `_list' on top of the `_head' llist, thus:
 * 	- `_list' is joined (see list_join() above)
 * 	- `_list' becomes the new head
 * 	- `_head' goes in `_list'->next
 * The new head of the llist is returned.
 * 
 * Example:	head=list_moveontop(head, list);
 */
#define list_moveontop(_head, _list)					\
({									\
 	l_list *_hmt=(l_list *)(_head), *_lmt=(l_list *)(_list);	\
 									\
 	if(_hmt != _lmt) {						\
		_hmt=(l_list *)list_join((typeof((_head)))_hmt, _lmt);	\
		_hmt=(l_list *)list_add((typeof((_head)))_hmt, _lmt);	\
	}								\
	(typeof((_head)))_hmt;						\
})

/*
 * list_for
 *
 * Pretty simple, use it in this way:
 *	 my_llist_ptr *index;
 *	 index=head_of_the_llist;
 *	 list_for(index) {
 *	 	do_something_with(index);
 *	 }
 *
 * WARNING: do not use expressions!! For example:
 *    DO NOT THIS
 * 	list_for(index=head_of_the_llist) {
 * 		...
 * 	}
 *    DO NOT THIS
 * In this case `index' will be set to `head_of_the_llist' each time and
 * you'll get an infinite loop;
 */
#define list_for(i) for(; (i); (i)=(typeof (i))(i)->next)

/*
 * list_count
 *
 * Returns the number of structs present in the llist
 */
#define list_count(_head)						\
({									\
	l_list *_lc=(l_list *)(_head);					\
	int _ic=0; 							\
									\
	list_for(_lc)							\
		_ic++;							\
	_ic;								\
})


/*
 * list_safe_for
 *
 * Use this for if you want to do something like:
 * 	list_for(list)
 * 		list_del(list);
 * If you are trying to do that, the normal list_for isn't safe! That's
 * because when list_del will free the current `list', list_for will use a
 * wrong list->next pointer, which doesn't exist at all.
 * list_for_del is the same as list_for but it takes a second parameter, which
 * is a list pointer. This pointer will be used to store, before executing the
 * code inside the for, the list->next pointer.
 * So this is a safe for. Example:
 *
 * 	l_list *ptr;
 * 	list_safe_for(list, ptr) {
 * 		... do stuff ...
 * 	}
 *
 * WARNING: do not use expressions in the arguments, (see the warning above
 * for the normal list_for)
 */
#define list_safe_for(_ii, _next_ptr)					\
for((_ii) ? (_next_ptr)=(typeof (_ii))(_ii)->next : 0; (_ii);		\
    (_ii)=(_next_ptr), (_ii) ? (_next_ptr)=(typeof (_ii))(_ii)->next : 0)


/* 
 * list_pos: returns the `pos'-th struct present in `list'
 */
#define list_pos(list, pos)						\
({									\
	 int _ip=0;							\
 	 l_list *_xp=(l_list *)(list);					\
 	 list_for(_xp) { 						\
 	 	if(_ip==(pos)) 						\
 			break;						\
		else 							\
 			_ip++;						\
 	 } 								\
 	 (typeof((list)))_xp;						\
})

/*
 * list_get_pos: returns the position of the `list' struct in the `head'
 * linked list, so that list_pos(head, list_get_pos(head, list)) == list
 * If `list' is not present in the linked list, -1 is returned.
 */
#define list_get_pos(head, list)					\
({									\
 	int _igp=0, _egp=0;						\
	l_list *_xgp=(l_list *)(head);					\
									\
	list_for(_xgp) {						\
		if(_xgp == (l_list *)(list)) {				\
			_egp=1;						\
			break;						\
		} else							\
			_igp++;						\
	}								\
	_egp ? _igp : -1;						\
})

/* 
 * list_destroy
 *
 * It traverse the entire `list' llist and calls list_del() on each 
 * struct.
 */
#define list_destroy(list)						\
do{ 									\
	l_list *_xd=(l_list *)(list), *_id, *_nextd;			\
	_id=_xd;							\
	list_safe_for(_id, _nextd)					\
		_xd=list_del(_xd, _id);					\
	(list)=0;							\
}while(0)


/*
 * list_copy_some
 *
 * It calls the `check_func' function for each struct of the `list' llist,
 * passing to it, as first argument, a pointer to the struct itself.
 * The other parameters to list_copy_some are passed to `check_func', for
 * example by calling:
 * 	list_copy_some(list, my_check_func, arg1, arg2, arg3);
 * the `my_check_func' will be called in this way:
 * 	my_check_func(arg1, arg2, arg3);
 * 
 * If the `check_func' function returns a non zero value, the struct is 
 * copied in a new allocated space.
 * All the copied structs form the replicated llist.
 * Its head is returned.
 * 
 * The `list' llist is not modified.
 */
#define list_copy_some(list, check_func, func_args...)			\
({									\
 	l_list *_ncs=0, *_hcs=0, *_tcs=0, *_lcs=(l_list *)(list);	\
									\
	list_for(_lcs) {						\
 		if(!check_func(((typeof((list)))_lcs), ## func_args ))	\
 			continue;					\
 									\
 		_ncs=(l_list *)list_dup(((typeof((list)))_lcs));	\
 		if(!_hcs) _hcs=_ncs;					\
 									\
		_tcs=list_append(0, _tcs, _ncs);			\
	}								\
 									\
 	(typeof((list)))_hcs;						\
})

/*
 * list_copy_all
 *
 * It copies the entire `list' llist in a new allocated one.
 * It returns the head to the replicated llist.
 * The `list' llist is not modified.
 */
#define list_copy_all_yes(_nil)	(1)
#define list_copy_all(list)	list_copy_some((list), list_copy_all_yes)
 
/*
 * Here below there are the definitions for the linked list with a counter.
 * The arguments format is:
 * l_list **_head, int *_counter, l_list *list
 */

#define clist_add(_head, _counter, _list)				\
do{									\
	if(!(*(_counter)) || !(*(_head)))				\
		list_init(*(_head), (_list));				\
	else								\
		*((_head))=list_add(*(_head), (_list));			\
	(*(_counter))++;						\
}while(0)

#define clist_append(_head, _tail, _counter, _list)			\
do{									\
	l_list *_tca=0, **_targv=(l_list **)(_tail);			\
	if((_tail))							\
		_tca=*_targv;						\
	if(!(*(_counter)) || !(*(_head)))				\
		list_init(*(_head), (_list));				\
	else {								\
		_tca=(l_list *)list_append(*(_head), _tca, (_list));	\
		if(_targv)						\
			(*_targv)=_tca;					\
	}								\
	(*(_counter))++;                                                \
}while(0)

#define clist_del(_head, _counter, _list)				\
do{									\
	if((*(_counter)) > 0) {						\
		*((_head))=list_del(*(_head), (_list));			\
		(*(_counter))--;					\
	}								\
}while(0)

#define clist_ins(_head, _counter, _list)				\
do{									\
        if(!(*(_counter)) || !(*(_head)))				\
		clist_add((_head), (_counter), (_list));		\
        else {								\
                list_ins(*(_head), (_list));                            \
        	(*(_counter))++;					\
	}								\
}while(0)

#define clist_join(_head, _counter, _list)                              \
do{                  							\
	if((*(_counter)) > 0) {						\
		*((_head))=list_join((*(_head)), _list);		\
		(*(_counter))--;					\
	}								\
} while(0)
	

/* 
 * Zeros the `counter' and set the head pointer to 0.
 * usage: head=clist_init(&counter);
 */
#define clist_init(_counter)						\
({									\
	*(_counter)=0;							\
	0;								\
})

#define clist_destroy(_head, _counter)					\
({									\
 	list_destroy(*((_head)));					\
 	(*(_head))=0;							\
 	(*(_counter))=0;						\
 	0;								\
})

/*
 * clist_qsort
 *
 * It qsorts the `_head' llist, which has `_counter' elements.
 * The `_cmp_func' function will be used to compare two llist.
 * The new head of the llist is returned. Example:
 * 	head=clist_qsort(head, counter, my_cmp_func);
 * `counter' can be also 0, but it's better if you've counted already.
 * 
 * Btw, this function just calls qsort(3), this is how it works:
 * 	- first of all it counts how many elements there are in the llist.
 * 	  This is done only if `_counter' is 0.
 * 	- it uses a temporary callocated array to store all the pointers to the
 * 	  elements of the llist. 
 * 	  tmp[0]=_head; tmp[1]=_head->next; tmp[..]=_head->next->..
 * 	- it calls qsort(3) on the tmp array. Note that qsort gives the
 *        address of &tmp[x] and &tmp[y] to `_cmp_func()', thus `_cmp_func()'
 *        should be aware of this.
 * 	- it follows the new order of `tmp' and appends each array element in
 * 	  a new llist.
 * 	- the head of the new llist is returned.
 */
#define clist_qsort(_head, _counter, _cmp_func)				\
({									\
	l_list *_hcq=(l_list *)(_head), *_ncq, *_hecq, *_tcq;		\
	int _icq=0, _ccq;						\
									\
	_ccq = !(_counter) ? list_count(_hcq) : (_counter);		\
	l_list *_tmp_list[_ccq];					\
									\
	_ncq=_hcq;							\
	list_for(_ncq) {						\
		_tmp_list[_icq]=_ncq;					\
		_icq++;							\
	}								\
									\
	qsort(_tmp_list, _ccq, sizeof(l_list *), (_cmp_func));		\
									\
	_tcq=0;								\
	_hecq=_tmp_list[0];						\
	for(_icq=0; _icq<_ccq; _icq++)					\
		_tcq=(l_list *)list_append(0, _tcq, _tmp_list[_icq]);	\
									\
	(typeof((_head)))_hecq;						\
})									\

#endif /*LLIST_C*/
