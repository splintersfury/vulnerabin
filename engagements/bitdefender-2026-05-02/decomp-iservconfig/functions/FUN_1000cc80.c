void __fastcall FUN_1000cc80(void *param_1)

{
  FUN_1000cfc0(param_1,(int *)0x12);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_1000cc90 @ 1000cc90

undefined1 __thiscall
FUN_1000cc90(void *this,undefined1 (*param_1) [16],uint param_2,undefined1 (*param_3) [16])

{
  undefined1 *puVar1;
  undefined1 (*pauVar2) [16];
  undefined1 (*pauVar3) [16];
  int iVar4;
  wchar_t *_Src;
  int iVar5;
  errno_t eVar6;
  size_t _MaxCount;
  int iVar7;
  
  if ((((param_3 != (undefined1 (*) [16])0x0) && (param_1 != (undefined1 (*) [16])0x0)) &&
      (param_2 != 0)) && (param_3 != param_1)) {
    pauVar2 = FUN_1002feea(param_3,(undefined1 (*) [16])&DAT_1005ed3c);
    if (pauVar2 == (undefined1 (*) [16])0x0) {
      pauVar2 = param_3;
      do {
        puVar1 = *pauVar2;
        pauVar2 = (undefined1 (*) [16])(*pauVar2 + 2);
      } while (*(short *)puVar1 != 0);
      if ((uint)((int)pauVar2 - (int)(*param_3 + 2) >> 1) < param_2) {
        _wcscpy_s((wchar_t *)param_1,param_2,(wchar_t *)param_3);
        return 1;
      }
    }
    else {
      *(undefined2 *)*param_1 = 0;
      FUN_10034931((wchar_t *)param_1,param_2,(wchar_t *)param_3,(int)pauVar2 - (int)param_3 >> 1);
      do {
        pauVar3 = FUN_1002feea(pauVar2,(undefined1 (*) [16])&DAT_1005ed44);
        iVar5 = DAT_1006b650;
        if (pauVar3 == (undefined1 (*) [16])0x0) break;
        pauVar3 = (undefined1 (*) [16])(*pauVar3 + 4);
        _MaxCount = (int)pauVar3 - (int)pauVar2 >> 1;
        iVar7 = DAT_1006b64c;
        if (DAT_1006b64c == DAT_1006b650) {
LAB_1000cdcb:
          iVar5 = FUN_10034a23((wchar_t *)param_1,param_2,(wchar_t *)pauVar2,_MaxCount);
        }
        else {
          do {
            iVar4 = _wcsncmp((wchar_t *)pauVar2,*(wchar_t **)(iVar7 + 8),_MaxCount);
            if (iVar4 == 0) break;
            iVar7 = iVar7 + 0xc;
          } while (iVar7 != iVar5);
          if (iVar7 == DAT_1006b650) goto LAB_1000cdcb;
          _Src = (wchar_t *)FUN_1000cfc0(this,*(int **)(iVar7 + 4));
          iVar5 = _wcscat_s((wchar_t *)param_1,param_2,_Src);
        }
        if (iVar5 != 0) break;
        pauVar2 = FUN_1002feea(pauVar3,(undefined1 (*) [16])&DAT_1005ed3c);
        if (pauVar2 == (undefined1 (*) [16])0x0) {
          eVar6 = _wcscat_s((wchar_t *)param_1,param_2,(wchar_t *)pauVar3);
          if (eVar6 == 0) {
            return 1;
          }
          break;
        }
        iVar5 = FUN_10034a23((wchar_t *)param_1,param_2,(wchar_t *)pauVar3,
                             (int)pauVar2 - (int)pauVar3 >> 1);
      } while (iVar5 == 0);
      pauVar2 = param_3;
      do {
        puVar1 = *pauVar2;
        pauVar2 = (undefined1 (*) [16])(*pauVar2 + 2);
      } while (*(short *)puVar1 != 0);
      if ((uint)((int)pauVar2 - (int)(*param_3 + 2) >> 1) < param_2) {
        _wcscpy_s((wchar_t *)param_1,param_2,(wchar_t *)param_3);
      }
    }
  }
  return 0;
}


// FUNCTION_END

// FUNCTION_START: FUN_1000ce80 @ 1000ce80

int __thiscall FUN_1000ce80(void *this,undefined1 (*param_1) [16])

{
  short *psVar1;
  short sVar2;
  int iVar3;
  int *piVar4;
  undefined1 *puVar5;
  int *piVar6;
  undefined1 (*pauVar7) [16];
  short *psVar8;
  undefined1 (*pauVar9) [16];
  int iVar10;
  int *local_c;
  
  piVar6 = DAT_1006b650;
  if ((param_1 != (undefined1 (*) [16])0x0) && (*(short *)*param_1 != 0)) {
    pauVar9 = param_1;
    do {
      puVar5 = *pauVar9;
      pauVar9 = (undefined1 (*) [16])(*pauVar9 + 2);
    } while (*(short *)puVar5 != 0);
    iVar10 = (int)pauVar9 - (int)(*param_1 + 2) >> 1;
    local_c = DAT_1006b64c;
    if (DAT_1006b64c != DAT_1006b650) {
      do {
        pauVar9 = (undefined1 (*) [16])local_c[2];
        iVar3 = *local_c;
        piVar4 = (int *)local_c[1];
        pauVar7 = FUN_1002feea(param_1,pauVar9);
        if (pauVar7 != (undefined1 (*) [16])0x0) {
          psVar8 = (short *)FUN_1000cfc0(this,piVar4);
          psVar1 = psVar8 + 1;
          do {
            sVar2 = *psVar8;
            psVar8 = psVar8 + 1;
          } while (sVar2 != 0);
          for (pauVar7 = FUN_1002feea((undefined1 (*) [16])(*pauVar7 + iVar3 * 2),pauVar9);
              iVar10 = iVar10 + (((int)psVar8 - (int)psVar1 >> 1) - iVar3),
              pauVar7 != (undefined1 (*) [16])0x0;
              pauVar7 = FUN_1002feea((undefined1 (*) [16])(*pauVar7 + iVar3 * 2),pauVar9)) {
          }
        }
        local_c = local_c + 3;
      } while (local_c != piVar6);
    }
    return iVar10;
  }
  return 0;
}


// FUNCTION_END

// FUNCTION_START: FUN_1000cf70 @ 1000cf70