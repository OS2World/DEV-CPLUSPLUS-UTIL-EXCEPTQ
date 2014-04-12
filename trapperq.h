/*-------------------------------------------------------------------*/
/* V2.0 Exception handler structure definitions for use with IBM C/2 */
struct _EXCEPTIONREGISTRATIONRECORD {
      struct _EXCEPTIONREGISTRATIONRECORD * prev_structure;
      PFN Handler;
};
typedef struct _EXCEPTIONREGISTRATIONRECORD    EXCEPTIONREGISTRATIONRECORD;
typedef struct _EXCEPTIONREGISTRATIONRECORD * PEXCEPTIONREGISTRATIONRECORD;
USHORT EXPENTRY SETEXCEPT(PEXCEPTIONREGISTRATIONRECORD);
/*------ Must be the first statement after decalration of main or threads --*/
#define EXCEPT_REGISTER()  \
    EXCEPTIONREGISTRATIONRECORD ExceptReg; \
    rc=SETEXCEPT(&ExceptReg);
