undefined1 * __thiscall FUN_1001b440(void *this,undefined1 *param_1,undefined1 *param_2)

{
  int iVar1;
  code *pcVar2;
  int iVar3;
  uint uVar4;
  undefined1 *puVar5;
  undefined1 *puVar6;
  uint uVar7;
  undefined1 *puVar8;
  undefined1 *puVar9;
  undefined1 *puVar10;
  undefined4 local_18;
  undefined4 local_14;
  
                    /* WARNING: Load size is inaccurate */
  iVar1 = *this;
  iVar3 = *(int *)((int)this + 4) - iVar1 >> 4;
  if (iVar3 == 0xfffffff) {
    FUN_10017fa0();
    pcVar2 = (code *)swi(3);
    puVar6 = (undefined1 *)(*pcVar2)();
    return puVar6;
  }
  uVar4 = iVar3 + 1;
  uVar7 = *(int *)((int)this + 8) - iVar1 >> 4;
  if (0xfffffff - (uVar7 >> 1) < uVar7) {
    uVar7 = 0xfffffff;
  }
  else {
    uVar7 = (uVar7 >> 1) + uVar7;
    if (uVar7 < uVar4) {
      uVar7 = uVar4;
    }
  }
  puVar5 = (undefined1 *)FUN_1001ab40(uVar7);
  puVar9 = puVar5 + ((int)param_1 - iVar1 & 0xfffffff0);
  *puVar9 = 0;
  *(undefined8 *)(puVar9 + 8) = 0;
  local_18 = CONCAT31(local_18._1_3_,*param_2);
  *puVar9 = 4;
  *(undefined4 *)(puVar9 + 8) = local_18;
  *(undefined4 *)(puVar9 + 0xc) = local_14;
                    /* WARNING: Load size is inaccurate */
  puVar6 = *this;
  puVar8 = *(undefined1 **)((int)this + 4);
  puVar10 = puVar5;
  if (param_1 != puVar8) {
    FUN_1001bcd0(puVar6,param_1,puVar5);
    puVar8 = *(undefined1 **)((int)this + 4);
    puVar6 = param_1;
    puVar10 = puVar9 + 0x10;
  }
  FUN_1001bcd0(puVar6,puVar8,puVar10);
  FUN_1001b840(this,(int)puVar5,uVar4,uVar7);
  return puVar9;
}


// FUNCTION_END

// FUNCTION_START: FUN_1001b520 @ 1001b520