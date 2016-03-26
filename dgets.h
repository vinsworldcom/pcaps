#ifndef DGETS_H
#define DGETS_H

#if BUILDING_DLL
__declspec(dllexport) char *dgets(FILE *, int, char);
#else
char *dgets(FILE *, int, char);
#endif

#endif
