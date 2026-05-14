void __thiscall FUN_10018a30(void *this,undefined4 *param_1,uint *param_2)

{
  int *piVar1;
  code *pcVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  int *piVar6;
  int *piVar7;
  undefined1 uVar8;
  uint uVar9;
  int *local_28;
  void *local_1c;
  undefined1 *puStack_18;
  undefined4 local_14;
  
  local_14 = 0xffffffff;
  puStack_18 = &LAB_1004f42d;
  local_1c = ExceptionList;
  ExceptionList = &local_1c;
                    /* WARNING: Load size is inaccurate */
  piVar1 = *this;
  uVar9 = 0;
  local_28 = (int *)piVar1[1];
  piVar7 = piVar1;
  if (*(char *)((int)local_28 + 0xd) == '\0') {
    piVar6 = local_28;
    do {
      local_28 = piVar6;
      if (*param_2 <= (uint)local_28[4]) {
        piVar6 = (int *)*local_28;
        piVar7 = local_28;
      }
      else {
        piVar6 = (int *)local_28[2];
      }
      uVar9 = (uint)(*param_2 <= (uint)local_28[4]);
    } while (*(char *)((int)piVar6 + 0xd) == '\0');
  }
  if ((*(char *)((int)piVar7 + 0xd) == '\0') && ((uint)piVar7[4] <= *param_2)) {
    uVar8 = 0;
  }
  else {
    if (*(int *)((int)this + 4) == 0x5d1745d) {
      FUN_10001840();
      pcVar2 = (code *)swi(3);
      (*pcVar2)();
      return;
    }
    local_14 = 0;
    piVar7 = (int *)operator_new(0x2c);
    piVar7[4] = *param_2;
    piVar7[5] = 0;
    piVar7[9] = 0;
    piVar7[10] = 0;
    uVar3 = param_2[2];
    uVar4 = param_2[3];
    uVar5 = param_2[4];
    piVar7[5] = param_2[1];
    piVar7[6] = uVar3;
    piVar7[7] = uVar4;
    piVar7[8] = uVar5;
    *(undefined8 *)(piVar7 + 9) = *(undefined8 *)(param_2 + 5);
    *(undefined2 *)(param_2 + 1) = 0;
    param_2[5] = 0;
    param_2[6] = 7;
    *piVar7 = (int)piVar1;
    piVar7[1] = (int)piVar1;
    piVar7[2] = (int)piVar1;
    *(undefined2 *)(piVar7 + 3) = 0;
    piVar7 = Insert_node(this,local_28,uVar9,piVar7);
    uVar8 = 1;
  }
  *param_1 = piVar7;
  *(undefined1 *)(param_1 + 1) = uVar8;
  ExceptionList = local_1c;
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10018b80 @ 10018b80