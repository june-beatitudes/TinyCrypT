#ifndef TCT_INTERNAL_CBMC_H
#define TCT_INTERNAL_CBMC_H

#ifdef CBMC

#define __func_contract__(x) x
#define __loop_contract__(x) x
#define requires(x) __CPROVER_requires (x)
#define ensures(x) __CPROVER_ensures (x)

#define is_fresh(x, n) __CPROVER_is_fresh (x, n)
#define memory_slice(x, n) __CPROVER_object_upto (x, n)
#define entire_object(x) __CPROVER_object_whole (x)
#define is_writable(x, n) __CPROVER_w_ok (x, n)
#define is_readable(x, n) __CPROVER_r_ok (x, n)

#define loop_invariant(x) __CPROVER_loop_invariant (x)
#define loop_decreases(x) __CPROVER_decreases (x)
#define assigns(x) __CPROVER_assigns (x)

#else

#define __func_contract__(x)
#define __loop_contract__(x)

#endif

#endif
