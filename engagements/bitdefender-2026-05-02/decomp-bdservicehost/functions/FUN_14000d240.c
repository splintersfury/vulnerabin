undefined8 FUN_14000d240(longlong *param_1)

{
  short sVar1;
  short *psVar2;
  longlong lVar3;
  DWORD DVar4;
  BOOL BVar5;
  LPWSTR pWVar6;
  ulonglong uVar7;
  DWORD DVar8;
  ulonglong uVar9;
  ulonglong uVar10;
  
  pWVar6 = (LPWSTR)*param_1;
  uVar9 = 0;
  if ((pWVar6 == (LPWSTR)0x0) || (*(longlong *)(pWVar6 + -6) == 0)) {
    uVar7 = uVar9;
    if (pWVar6 == (LPWSTR)0x0) {
      FUN_140014f60(param_1,0x40);
      pWVar6 = (LPWSTR)*param_1;
      uVar7 = 0;
    }
  }
  else {
    uVar7 = (ulonglong)*(uint *)(*(longlong *)(pWVar6 + -6) + 0x10);
  }
  DVar4 = GetModuleFileNameW((HMODULE)0x0,pWVar6,(DWORD)uVar7);
  psVar2 = (short *)*param_1;
  sVar1 = *psVar2;
  uVar7 = uVar9;
  while (sVar1 != 0) {
    uVar7 = uVar7 + 1;
    sVar1 = psVar2[uVar7];
  }
  lVar3 = *(longlong *)(psVar2 + -6);
  uVar10 = uVar9;
  if (lVar3 != 0) {
    uVar10 = *(ulonglong *)(lVar3 + 0x10);
  }
  if (uVar7 <= uVar10) {
    *(ulonglong *)(lVar3 + 8) = uVar7;
    pWVar6 = (LPWSTR)*param_1;
    if (((pWVar6 == (LPWSTR)0x0) || (*(longlong *)(pWVar6 + -6) == 0)) ||
       ((*(int *)(pWVar6 + -8) == 0xabcd &&
        ((*(int *)(pWVar6 + -2) == 0xabcd &&
         (*(int *)(pWVar6 + *(longlong *)(*(longlong *)(pWVar6 + -6) + 0x10) + 1) == 0xabcd)))))) {
      if (DVar4 != 0) {
        if ((pWVar6 == (LPWSTR)0x0) || (*(longlong *)(pWVar6 + -6) == 0)) {
          DVar8 = 0;
        }
        else {
          DVar8 = (DWORD)*(undefined8 *)(*(longlong *)(pWVar6 + -6) + 0x10);
        }
        if (DVar8 != DVar4) {
          if (pWVar6 == (LPWSTR)0x0) {
            FUN_140014f60(param_1,0x40);
            pWVar6 = (LPWSTR)*param_1;
          }
          BVar5 = PathRemoveFileSpecW(pWVar6);
          psVar2 = (short *)*param_1;
          sVar1 = *psVar2;
          uVar7 = uVar9;
          while (sVar1 != 0) {
            uVar7 = uVar7 + 1;
            sVar1 = psVar2[uVar7];
          }
          lVar3 = *(longlong *)(psVar2 + -6);
          uVar10 = uVar9;
          if (lVar3 != 0) {
            uVar10 = *(ulonglong *)(lVar3 + 0x10);
          }
          if (uVar7 <= uVar10) {
            *(ulonglong *)(lVar3 + 8) = uVar7;
            pWVar6 = (LPWSTR)*param_1;
            if (((pWVar6 == (LPWSTR)0x0) || (*(longlong *)(pWVar6 + -6) == 0)) ||
               ((*(int *)(pWVar6 + -8) == 0xabcd &&
                ((*(int *)(pWVar6 + -2) == 0xabcd &&
                 (*(int *)(pWVar6 + *(longlong *)(*(longlong *)(pWVar6 + -6) + 0x10) + 1) == 0xabcd)
                 ))))) {
              if (BVar5 == 0) {
                return 0;
              }
              if (pWVar6 == (LPWSTR)0x0) {
                FUN_140014f60(param_1,0x40);
                pWVar6 = (LPWSTR)*param_1;
              }
              pWVar6 = PathAddBackslashW(pWVar6);
              psVar2 = (short *)*param_1;
              sVar1 = *psVar2;
              uVar7 = uVar9;
              while (sVar1 != 0) {
                uVar7 = uVar7 + 1;
                sVar1 = psVar2[uVar7];
              }
              lVar3 = *(longlong *)(psVar2 + -6);
              if (lVar3 != 0) {
                uVar9 = *(ulonglong *)(lVar3 + 0x10);
              }
              if (uVar7 <= uVar9) {
                *(ulonglong *)(lVar3 + 8) = uVar7;
                lVar3 = *param_1;
                if (((lVar3 == 0) || (*(longlong *)(lVar3 + -0xc) == 0)) ||
                   ((*(int *)(lVar3 + -0x10) == 0xabcd &&
                    ((*(int *)(lVar3 + -4) == 0xabcd &&
                     (*(int *)(lVar3 + 2 + *(longlong *)(*(longlong *)(lVar3 + -0xc) + 0x10) * 2) ==
                      0xabcd)))))) {
                  if (pWVar6 == (LPWSTR)0x0) {
                    return 0;
                  }
                  return 1;
                }
              }
            }
          }
          goto LAB_14000d45e;
        }
      }
      return 0;
    }
  }
LAB_14000d45e:
                    /* WARNING: Subroutine does not return */
  _CxxThrowException((void *)0x0,(ThrowInfo *)0x0);
}


// FUNCTION_END

// FUNCTION_START: FUN_14000d470 @ 14000d470