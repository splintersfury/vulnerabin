undefined4 * __thiscall FUN_10018b80(void *this,undefined4 *param_1,uint *param_2)

{
  int *piVar1;
  uint *puVar2;
  code *pcVar3;
  uint uVar4;
  undefined1 uVar5;
  int *piVar6;
  int *piVar7;
  undefined4 *puVar8;
  uint *puVar9;
  int *piVar10;
  uint uVar11;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004f465;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
                    /* WARNING: Load size is inaccurate */
  piVar1 = *this;
  uVar11 = 0;
  piVar10 = (int *)piVar1[1];
  piVar7 = piVar1;
  if (*(char *)((int)piVar10 + 0xd) == '\0') {
    piVar6 = piVar10;
    do {
      piVar10 = piVar6;
      if (*param_2 <= (uint)piVar10[4]) {
        piVar6 = (int *)*piVar10;
        piVar7 = piVar10;
      }
      else {
        piVar6 = (int *)piVar10[2];
      }
      uVar11 = (uint)(*param_2 <= (uint)piVar10[4]);
    } while (*(char *)((int)piVar6 + 0xd) == '\0');
  }
  if ((*(char *)((int)piVar7 + 0xd) == '\0') && ((uint)piVar7[4] <= *param_2)) {
    uVar5 = 0;
  }
  else {
    if (*(int *)((int)this + 4) == 0x5d1745d) {
      FUN_10001840();
      pcVar3 = (code *)swi(3);
      puVar8 = (undefined4 *)(*pcVar3)();
      return puVar8;
    }
    local_8 = 0;
    piVar7 = (int *)operator_new(0x2c);
    local_8 = 1;
    piVar7[4] = *param_2;
    puVar2 = (uint *)param_2[1];
    piVar7[5] = 0;
    piVar7[9] = 0;
    piVar7[10] = 7;
    puVar9 = puVar2;
    do {
      uVar4 = *puVar9;
      puVar9 = (uint *)((int)puVar9 + 2);
    } while ((short)uVar4 != 0);
    FUN_10001d40(piVar7 + 5,puVar2,(int)puVar9 - ((int)puVar2 + 2) >> 1);
    *piVar7 = (int)piVar1;
    piVar7[1] = (int)piVar1;
    piVar7[2] = (int)piVar1;
    *(undefined2 *)(piVar7 + 3) = 0;
    piVar7 = Insert_node(this,piVar10,uVar11,piVar7);
    uVar5 = 1;
  }
  *(undefined1 *)(param_1 + 1) = uVar5;
  *param_1 = piVar7;
  ExceptionList = local_10;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_10018cc0 @ 10018cc0