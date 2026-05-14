undefined1 * __thiscall FUN_1001b1d0(void *this,undefined1 *param_1,undefined8 *param_2)

{
  int iVar1;
  code *pcVar2;
  int iVar3;
  uint uVar4;
  undefined1 *puVar5;
  undefined1 *puVar6;
  undefined1 *puVar7;
  undefined1 *puVar8;
  uint uVar9;
  undefined1 *puVar10;
  
                    /* WARNING: Load size is inaccurate */
  iVar1 = *this;
  iVar3 = *(int *)((int)this + 4) - iVar1 >> 4;
  if (iVar3 != 0xfffffff) {
    uVar4 = iVar3 + 1;
    uVar9 = *(int *)((int)this + 8) - iVar1 >> 4;
    if (0xfffffff - (uVar9 >> 1) < uVar9) {
      uVar9 = 0xfffffff;
    }
    else {
      uVar9 = (uVar9 >> 1) + uVar9;
      if (uVar9 < uVar4) {
        uVar9 = uVar4;
      }
    }
    puVar5 = (undefined1 *)FUN_1001ab40(uVar9);
    puVar6 = puVar5 + ((int)param_1 - iVar1 & 0xfffffff0);
    *puVar6 = 0;
    *(undefined8 *)(puVar6 + 8) = 0;
    FUN_1001bd50(puVar6,param_2);
                    /* WARNING: Load size is inaccurate */
    puVar8 = *(undefined1 **)((int)this + 4);
    puVar10 = *this;
    puVar7 = puVar5;
    if (param_1 != puVar8) {
      FUN_1001bcd0(*this,param_1,puVar5);
      puVar8 = *(undefined1 **)((int)this + 4);
      puVar7 = puVar6 + 0x10;
      puVar10 = param_1;
    }
    FUN_1001bcd0(puVar10,puVar8,puVar7);
    FUN_1001b840(this,(int)puVar5,uVar4,uVar9);
    return puVar6;
  }
  FUN_10017fa0();
  pcVar2 = (code *)swi(3);
  puVar8 = (undefined1 *)(*pcVar2)();
  return puVar8;
}


// FUNCTION_END

// FUNCTION_START: FUN_1001b2a0 @ 1001b2a0