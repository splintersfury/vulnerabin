ulonglong * FUN_14000d890(longlong param_1,ulonglong *param_2,longlong *param_3,byte param_4)

{
  longlong lVar1;
  int iVar2;
  longlong lVar3;
  longlong lVar4;
  longlong lVar5;
  ulonglong uVar6;
  ulonglong uVar7;
  
  uVar7 = param_3[1] + *param_3;
  lVar3 = **(longlong **)(param_1 + 0x38);
  if ((*(byte *)(param_1 + 0x70) & 2) == 0) {
    uVar6 = **(ulonglong **)(param_1 + 0x40);
    if ((uVar6 != 0) && (*(ulonglong *)(param_1 + 0x68) < uVar6)) {
      *(ulonglong *)(param_1 + 0x68) = uVar6;
    }
  }
  else {
    uVar6 = 0;
  }
  lVar4 = *(longlong *)(param_1 + 0x68);
  lVar5 = **(longlong **)(param_1 + 0x18);
  if (((ulonglong)(lVar4 - lVar5 >> 1) < uVar7) ||
     ((uVar7 != 0 &&
      ((((param_4 & 1) != 0 && (lVar3 == 0)) || (((param_4 & 2) != 0 && (uVar6 == 0)))))))) {
    *param_2 = 0xffffffffffffffff;
  }
  else {
    lVar1 = lVar5 + uVar7 * 2;
    if (((param_4 & 1) != 0) && (lVar3 != 0)) {
      **(longlong **)(param_1 + 0x38) = lVar1;
      **(undefined4 **)(param_1 + 0x50) = (int)(lVar4 - lVar1 >> 1);
    }
    if (((param_4 & 2) != 0) && (uVar6 != 0)) {
      iVar2 = **(int **)(param_1 + 0x58);
      lVar3 = **(longlong **)(param_1 + 0x40);
      **(longlong **)(param_1 + 0x20) = lVar5;
      **(longlong **)(param_1 + 0x40) = lVar1;
      **(undefined4 **)(param_1 + 0x58) = (int)((lVar3 + (longlong)iVar2 * 2) - lVar1 >> 1);
    }
    *param_2 = uVar7;
  }
  param_2[1] = 0;
  param_2[2] = 0;
  return param_2;
}


// FUNCTION_END

// FUNCTION_START: FUN_14000d9a0 @ 14000d9a0