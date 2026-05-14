ulonglong *
FUN_14000d9a0(longlong param_1,ulonglong *param_2,longlong param_3,int param_4,byte param_5)

{
  longlong lVar1;
  int iVar2;
  longlong lVar3;
  longlong lVar4;
  longlong lVar5;
  ulonglong uVar6;
  ulonglong uVar7;
  ulonglong uVar8;
  
  lVar3 = **(longlong **)(param_1 + 0x38);
  if ((*(byte *)(param_1 + 0x70) & 2) == 0) {
    uVar7 = **(ulonglong **)(param_1 + 0x40);
    if ((uVar7 != 0) && (*(ulonglong *)(param_1 + 0x68) < uVar7)) {
      *(ulonglong *)(param_1 + 0x68) = uVar7;
    }
  }
  else {
    uVar7 = 0;
  }
  lVar4 = *(longlong *)(param_1 + 0x68);
  lVar5 = **(longlong **)(param_1 + 0x18);
  uVar8 = lVar4 - lVar5 >> 1;
  if (param_4 == 0) {
    uVar6 = 0;
LAB_14000da67:
    uVar6 = uVar6 + param_3;
    if ((uVar6 <= uVar8) &&
       ((uVar6 == 0 ||
        ((((param_5 & 1) == 0 || (lVar3 != 0)) && (((param_5 & 2) == 0 || (uVar7 != 0)))))))) {
      lVar1 = lVar5 + uVar6 * 2;
      if (((param_5 & 1) != 0) && (lVar3 != 0)) {
        **(longlong **)(param_1 + 0x38) = lVar1;
        **(undefined4 **)(param_1 + 0x50) = (int)(lVar4 - lVar1 >> 1);
      }
      if (((param_5 & 2) != 0) && (uVar7 != 0)) {
        iVar2 = **(int **)(param_1 + 0x58);
        lVar3 = **(longlong **)(param_1 + 0x40);
        **(longlong **)(param_1 + 0x20) = lVar5;
        **(longlong **)(param_1 + 0x40) = lVar1;
        **(undefined4 **)(param_1 + 0x58) = (int)((lVar3 + (longlong)iVar2 * 2) - lVar1 >> 1);
      }
      *param_2 = uVar6;
      goto LAB_14000dae9;
    }
  }
  else if (param_4 == 1) {
    if ((param_5 & 3) != 3) {
      if ((param_5 & 1) == 0) {
        if (((param_5 & 2) != 0) && ((uVar7 != 0 || (lVar5 == 0)))) {
          uVar6 = (longlong)(uVar7 - lVar5) >> 1;
          goto LAB_14000da67;
        }
      }
      else if ((lVar3 != 0) || (lVar5 == 0)) {
        uVar6 = lVar3 - lVar5 >> 1;
        goto LAB_14000da67;
      }
    }
  }
  else {
    uVar6 = uVar8;
    if (param_4 == 2) goto LAB_14000da67;
  }
  *param_2 = 0xffffffffffffffff;
LAB_14000dae9:
  param_2[1] = 0;
  param_2[2] = 0;
  return param_2;
}


// FUNCTION_END

// FUNCTION_START: FUN_14000db20 @ 14000db20