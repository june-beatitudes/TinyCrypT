#ifndef TCT_INTERNAL_CBMC_H
#define TCT_INTERNAL_CBMC_H

#ifdef CBMC
#define __func_contract__(x) x
#define __loop_contract__(x) x
#else
#define __func_contract__(x)
#define __loop_contract__(x)
#endif

#endif
