void __thiscall FUN_1001b070(void *this,undefined1 *param_1,uint *param_2)

{
  int iVar1;
  code *pcVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  undefined1 *puVar6;
  void *this_00;
  uint uVar7;
  undefined1 *puVar8;
  undefined1 *puVar9;
  undefined1 *puVar10;
  undefined1 *puVar11;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004f72d;
  local_10 = ExceptionList;
  uVar3 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
                    /* WARNING: Load size is inaccurate */
  iVar1 = *this;
  iVar4 = *(int *)((int)this + 4) - iVar1 >> 4;
  if (iVar4 != 0xfffffff) {
    uVar5 = iVar4 + 1;
    uVar7 = *(int *)((int)this + 8) - iVar1 >> 4;
    if (0xfffffff - (uVar7 >> 1) < uVar7) {
      uVar7 = 0xfffffff;
    }
    else {
      uVar7 = (uVar7 >> 1) + uVar7;
      if (uVar7 < uVar5) {
        uVar7 = uVar5;
      }
    }
    puVar6 = (undefined1 *)FUN_1001ab40(uVar7);
    local_8 = 0;
    puVar10 = puVar6 + ((int)param_1 - iVar1 & 0xfffffff0);
    *(undefined8 *)(puVar10 + 8) = 0;
    *puVar10 = 3;
    this_00 = operator_new(0x18);
    local_8 = CONCAT31(local_8._1_3_,1);
    FUN_100056d0(this_00,param_2);
    *(void **)(puVar10 + 0xc) = this_00;
    *(void **)(puVar10 + 8) = this_00;
                    /* WARNING: Load size is inaccurate */
    puVar9 = *(undefined1 **)((int)this + 4);
    puVar8 = *this;
    puVar11 = puVar6;
    if (param_1 != puVar9) {
      FUN_1001bcd0(*this,param_1,puVar6);
      puVar9 = *(undefined1 **)((int)this + 4);
      puVar8 = param_1;
      puVar11 = puVar10 + 0x10;
    }
    FUN_1001bcd0(puVar8,puVar9,puVar11);
    FUN_1001b840(this,(int)puVar6,uVar5,uVar7);
    ExceptionList = local_10;
    FUN_1002e315(uVar3 ^ (uint)&stack0xfffffffc);
    return;
  }
  FUN_10017fa0();
  pcVar2 = (code *)swi(3);
  (*pcVar2)();
  return;
}


// FUNCTION_END

// FUNCTION_START: Catch_All@1001b1ab @ 1001b1ab