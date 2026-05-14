undefined1 * __thiscall FUN_1001b6c0(void *this,undefined1 *param_1,undefined1 *param_2)

{
  int iVar1;
  undefined4 uVar2;
  code *pcVar3;
  int iVar4;
  uint uVar5;
  undefined1 *puVar6;
  undefined1 *puVar7;
  undefined1 *puVar8;
  uint uVar9;
  undefined1 *puVar10;
  undefined1 *puVar11;
  
                    /* WARNING: Load size is inaccurate */
  iVar1 = *this;
  iVar4 = *(int *)((int)this + 4) - iVar1 >> 4;
  if (iVar4 != 0xfffffff) {
    uVar5 = iVar4 + 1;
    uVar9 = *(int *)((int)this + 8) - iVar1 >> 4;
    if (0xfffffff - (uVar9 >> 1) < uVar9) {
      uVar9 = 0xfffffff;
    }
    else {
      uVar9 = (uVar9 >> 1) + uVar9;
      if (uVar9 < uVar5) {
        uVar9 = uVar5;
      }
    }
    puVar6 = (undefined1 *)FUN_1001ab40(uVar9);
    puVar11 = puVar6 + ((int)param_1 - iVar1 & 0xfffffff0);
    *puVar11 = *param_2;
    uVar2 = *(undefined4 *)(param_2 + 0xc);
    *(undefined4 *)(puVar11 + 8) = *(undefined4 *)(param_2 + 8);
    *(undefined4 *)(puVar11 + 0xc) = uVar2;
    *param_2 = 0;
    *(undefined4 *)(param_2 + 8) = 0;
    *(undefined4 *)(param_2 + 0xc) = 0;
                    /* WARNING: Load size is inaccurate */
    puVar8 = *(undefined1 **)((int)this + 4);
    puVar10 = *this;
    puVar7 = puVar6;
    if (param_1 != puVar8) {
      FUN_1001bcd0(*this,param_1,puVar6);
      puVar8 = *(undefined1 **)((int)this + 4);
      puVar7 = puVar11 + 0x10;
      puVar10 = param_1;
    }
    FUN_1001bcd0(puVar10,puVar8,puVar7);
    FUN_1001b840(this,(int)puVar6,uVar5,uVar9);
    return puVar11;
  }
  FUN_10017fa0();
  pcVar3 = (code *)swi(3);
  puVar8 = (undefined1 *)(*pcVar3)();
  return puVar8;
}


// FUNCTION_END

// FUNCTION_START: FUN_1001b7a0 @ 1001b7a0