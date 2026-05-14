int * __thiscall FUN_10018550(void *this,int *param_1,int param_2,int param_3)

{
  int iVar1;
  uint *puVar2;
  code *pcVar3;
  void *pvVar4;
  int iVar5;
  uint uVar6;
  int *piVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  int iVar11;
  uint *puVar12;
  uint *puVar13;
  void *local_1c;
  undefined1 *puStack_18;
  undefined4 uStack_14;
  
  pvVar4 = ExceptionList;
  uStack_14 = 0xffffffff;
  puStack_18 = &LAB_1004f3a0;
  local_1c = ExceptionList;
  ExceptionList = &local_1c;
                    /* WARNING: Load size is inaccurate */
  puVar2 = *this;
  uVar9 = *(uint *)((int)this + 0xc);
  uVar10 = 0;
  puVar12 = puVar2;
  if (uVar9 != 0) {
    uVar10 = (param_2 - (int)puVar2 >> 2) * 0x20 + param_3;
    if (((int)uVar10 < 0) && (uVar10 != 0)) {
      iVar5 = -((~uVar10 >> 5) * 4 + 4);
    }
    else {
      iVar5 = (uVar10 >> 5) * 4;
    }
    puVar12 = (uint *)((int)puVar2 + iVar5);
    uVar10 = uVar10 & 0x1f;
  }
  iVar5 = ((int)puVar12 - (int)puVar2 >> 2) * 0x20 + uVar10;
  if (((int)uVar9 < 0) && (uVar9 != 0)) {
    iVar11 = -((~uVar9 >> 5) * 4 + 4);
  }
  else {
    iVar11 = (uVar9 >> 5) * 4;
  }
  puVar13 = puVar12;
  if (0x1e < uVar10) {
    puVar13 = puVar12 + 1;
  }
  uVar8 = -(uint)(uVar10 < 0x1f) & uVar10 + 1;
  while ((puVar13 != (uint *)((int)puVar2 + iVar11) || (uVar8 != (uVar9 & 0x1f)))) {
    if ((*puVar13 & 1 << ((byte)uVar8 & 0x1f)) == 0) {
      uVar6 = *puVar12 & ~(1 << (uVar10 & 0x1f));
    }
    else {
      uVar6 = *puVar12 | 1 << (uVar10 & 0x1f);
    }
    *puVar12 = uVar6;
    if (uVar10 < 0x1f) {
      uVar10 = uVar10 + 1;
    }
    else {
      uVar10 = 0;
      puVar12 = puVar12 + 1;
    }
    if (uVar8 < 0x1f) {
      uVar8 = uVar8 + 1;
    }
    else {
      uVar8 = 0;
      puVar13 = puVar13 + 1;
    }
  }
  uVar9 = *(int *)((int)this + 0xc) - 1;
  if (0x7fffffff < uVar9) {
    FUN_10014110();
    pcVar3 = (code *)swi(3);
    piVar7 = (int *)(*pcVar3)();
    return piVar7;
  }
                    /* WARNING: Load size is inaccurate */
  iVar11 = *this;
  uVar10 = *(int *)((int)this + 0xc) + 0x1eU >> 5;
  if ((uVar10 < (uint)(*(int *)((int)this + 4) - iVar11 >> 2)) &&
     (iVar1 = iVar11 + uVar10 * 4, iVar1 != *(int *)((int)this + 4))) {
    *(int *)((int)this + 4) = iVar1;
  }
  *(uint *)((int)this + 0xc) = uVar9;
  if ((uVar9 & 0x1f) != 0) {
    puVar2 = (uint *)(iVar11 + -4 + uVar10 * 4);
    *puVar2 = *puVar2 & (1 << (sbyte)(uVar9 & 0x1f)) - 1U;
                    /* WARNING: Load size is inaccurate */
    iVar11 = *this;
  }
  *param_1 = iVar11;
  param_1[1] = 0;
  if ((iVar5 < 0) && ((uint)param_1[1] < (uint)-iVar5)) {
    uVar9 = param_1[1] + iVar5;
    *param_1 = *param_1 + (~uVar9 >> 5) * -4 + -4;
  }
  else {
    uVar9 = param_1[1] + iVar5;
    *param_1 = *param_1 + (uVar9 >> 5) * 4;
  }
  param_1[1] = uVar9;
  param_1[1] = uVar9 & 0x1f;
  ExceptionList = pvVar4;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_10018730 @ 10018730