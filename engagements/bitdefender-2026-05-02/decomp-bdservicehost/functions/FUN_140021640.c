ulonglong FUN_140021640(longlong *param_1,longlong *param_2)

{
  longlong lVar1;
  longlong lVar2;
  undefined1 (*pauVar3) [16];
  code *pcVar4;
  ulonglong uVar5;
  ulonglong uVar6;
  ulonglong uVar7;
  int local_38 [4];
  uint *local_28;
  uint *local_18;
  
  lVar2 = *param_1;
  uVar7 = (*param_2 - lVar2 >> 2) * 0x20 + param_2[1];
  if (param_1[3] != 0x7fffffffffffffff) {
    pauVar3 = (undefined1 (*) [16])param_1[1];
    uVar6 = param_1[3] + 0x20U >> 5;
    local_38[0] = 0;
    uVar5 = (longlong)pauVar3 - lVar2 >> 2;
    if (uVar6 < uVar5) {
      param_1[1] = lVar2 + uVar6 * 4;
    }
    else if (uVar5 < uVar6) {
      if ((ulonglong)(param_1[2] - lVar2 >> 2) < uVar6) {
        FUN_1400267d0(param_1,uVar6,local_38);
      }
      else {
        uVar5 = (uVar6 - uVar5) * 4;
        FUN_140031e00(pauVar3,0,uVar5);
        param_1[1] = (longlong)pauVar3 + uVar5;
      }
    }
    uVar5 = param_1[3];
    if (uVar5 == 0) {
      param_1[3] = 1;
    }
    else {
      lVar2 = *param_1;
      if (((longlong)uVar5 < 0) && (uVar5 != 0)) {
        lVar1 = -((~uVar5 >> 5) * 4 + 4);
      }
      else {
        lVar1 = (uVar5 >> 5) * 4;
      }
      local_18 = (uint *)(lVar2 + lVar1);
      uVar6 = (ulonglong)((uint)uVar5 & 0x1f);
      uVar5 = uVar5 + 1;
      param_1[3] = uVar5;
      if (((longlong)uVar5 < 0) && (uVar5 != 0)) {
        lVar1 = -((~uVar5 >> 5) * 4 + 4);
      }
      else {
        lVar1 = (uVar5 >> 5) * 4;
      }
      local_28 = (uint *)(lVar2 + lVar1);
      uVar5 = (ulonglong)((uint)uVar5 & 0x1f);
      if (((longlong)uVar7 < 0) && (uVar7 != 0)) {
        lVar1 = -((~uVar7 >> 5) * 4 + 4);
      }
      else {
        lVar1 = (uVar7 >> 5) * 4;
      }
      while (((uint *)(lVar2 + lVar1) != local_18 || (((uint)uVar7 & 0x1f) != uVar6))) {
        if (uVar6 == 0) {
          uVar6 = 0x1f;
          local_18 = local_18 + -1;
        }
        else {
          uVar6 = uVar6 - 1;
        }
        if (uVar5 == 0) {
          uVar5 = 0x1f;
          local_28 = local_28 + -1;
        }
        else {
          uVar5 = uVar5 - 1;
        }
        if ((*local_18 & 1 << ((byte)uVar6 & 0x1f)) == 0) {
          *local_28 = *local_28 & ~(1 << ((uint)uVar5 & 0x1f));
        }
        else {
          *local_28 = *local_28 | 1 << ((uint)uVar5 & 0x1f);
        }
      }
    }
    return uVar7;
  }
  FUN_140021870();
  pcVar4 = (code *)swi(3);
  uVar7 = (*pcVar4)();
  return uVar7;
}


// FUNCTION_END

// FUNCTION_START: FUN_140021870 @ 140021870