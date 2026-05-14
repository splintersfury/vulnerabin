undefined8 * FUN_140028680(longlong *param_1,undefined8 *param_2,undefined8 *param_3)

{
  ulonglong uVar1;
  ulonglong uVar2;
  code *pcVar3;
  uint uVar4;
  longlong *plVar5;
  undefined8 *puVar6;
  longlong *plVar7;
  longlong *plVar8;
  ulonglong _Size;
  ulonglong uVar9;
  longlong *local_68;
  longlong *plStack_60;
  longlong *local_58;
  uint uStack_50;
  undefined4 uStack_4c;
  
  plVar5 = (longlong *)*param_1;
  local_58 = (longlong *)plVar5[1];
  uStack_50 = 0;
  local_68 = plVar5;
  if (*(char *)((longlong)local_58 + 0x19) == '\0') {
    uVar1 = param_3[2];
    uVar2 = param_3[3];
    plVar8 = local_58;
    do {
      plVar7 = plVar8 + 4;
      puVar6 = param_3;
      if (0xf < uVar2) {
        puVar6 = (undefined8 *)*param_3;
      }
      uVar9 = plVar8[6];
      if (0xf < (ulonglong)plVar8[7]) {
        plVar7 = (longlong *)*plVar7;
      }
      _Size = uVar9;
      if (uVar1 < uVar9) {
        _Size = uVar1;
      }
      local_58 = plVar8;
      uVar4 = memcmp(plVar7,puVar6,_Size);
      if (uVar4 == 0) {
        if (uVar9 < uVar1) {
          uVar4 = 0xffffffff;
        }
        else {
          uVar4 = (uint)(uVar1 < uVar9);
        }
      }
      if (-1 < (int)uVar4) {
        plVar7 = (longlong *)*plVar8;
        plVar5 = plVar8;
      }
      else {
        plVar7 = (longlong *)plVar8[2];
      }
      uStack_50 = (uint)(-1 < (int)uVar4);
      plVar8 = plVar7;
    } while (*(char *)((longlong)plVar7 + 0x19) == '\0');
  }
  plVar8 = local_68;
  if (*(char *)((longlong)plVar5 + 0x19) == '\0') {
    plVar7 = plVar5 + 4;
    uVar1 = plVar5[6];
    if (0xf < (ulonglong)plVar5[7]) {
      plVar7 = (longlong *)*plVar7;
    }
    uVar2 = param_3[2];
    puVar6 = param_3;
    if (0xf < (ulonglong)param_3[3]) {
      puVar6 = (undefined8 *)*param_3;
    }
    uVar9 = uVar2;
    if (uVar1 < uVar2) {
      uVar9 = uVar1;
    }
    uVar4 = memcmp(puVar6,plVar7,uVar9);
    if (uVar4 == 0) {
      if (uVar2 < uVar1) {
        uVar4 = 0xffffffff;
      }
      else {
        uVar4 = (uint)(uVar1 < uVar2);
      }
    }
    if (-1 < (int)uVar4) {
      *param_2 = plVar5;
      *(byte *)(param_2 + 1) = (byte)(uVar4 >> 0x1f);
      return param_2;
    }
  }
  if (param_1[1] != 0x333333333333333) {
    plStack_60 = (longlong *)0x0;
    local_68 = param_1;
    plVar5 = (longlong *)operator_new(0x50);
    plStack_60 = plVar5;
    FUN_14000e990(plVar5 + 4,param_3);
    FUN_14001de50((char *)(plVar5 + 8),'\0');
    *plVar5 = (longlong)plVar8;
    plVar5[1] = (longlong)plVar8;
    plVar5[2] = (longlong)plVar8;
    *(undefined2 *)(plVar5 + 3) = 0;
    plStack_60 = (longlong *)CONCAT44(uStack_4c,uStack_50);
    local_68 = local_58;
    plVar5 = FUN_140028900(param_1,(longlong *)&local_68,plVar5);
    *param_2 = plVar5;
    *(undefined1 *)(param_2 + 1) = 1;
    return param_2;
  }
  FUN_140018340();
  pcVar3 = (code *)swi(3);
  puVar6 = (undefined8 *)(*pcVar3)();
  return puVar6;
}


// FUNCTION_END

// FUNCTION_START: FUN_140028870 @ 140028870