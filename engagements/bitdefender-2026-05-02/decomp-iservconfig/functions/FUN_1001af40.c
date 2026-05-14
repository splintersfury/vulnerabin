char * __thiscall FUN_1001af40(void *this,undefined1 *param_1,char *param_2)

{
  char cVar1;
  int iVar2;
  code *pcVar3;
  int iVar4;
  uint uVar5;
  char *pcVar6;
  char *pcVar7;
  uint uVar8;
  undefined1 *puVar9;
  undefined1 *puVar10;
  char *pcVar11;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1004f700;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
                    /* WARNING: Load size is inaccurate */
  iVar2 = *this;
  iVar4 = *(int *)((int)this + 4) - iVar2 >> 4;
  if (iVar4 != 0xfffffff) {
    uVar5 = iVar4 + 1;
    uVar8 = *(int *)((int)this + 8) - iVar2 >> 4;
    if (0xfffffff - (uVar8 >> 1) < uVar8) {
      uVar8 = 0xfffffff;
    }
    else {
      uVar8 = (uVar8 >> 1) + uVar8;
      if (uVar8 < uVar5) {
        uVar8 = uVar5;
      }
    }
    pcVar6 = (char *)FUN_1001ab40(uVar8);
    local_8 = 0;
    pcVar7 = pcVar6 + ((int)param_1 - iVar2 & 0xfffffff0);
    cVar1 = *param_2;
    *pcVar7 = cVar1;
    FUN_1000f600(pcVar7 + 8,cVar1);
                    /* WARNING: Load size is inaccurate */
    puVar10 = *(undefined1 **)((int)this + 4);
    puVar9 = *this;
    pcVar11 = pcVar6;
    if (param_1 != puVar10) {
      FUN_1001bcd0(*this,param_1,pcVar6);
      puVar10 = *(undefined1 **)((int)this + 4);
      puVar9 = param_1;
      pcVar11 = pcVar7 + 0x10;
    }
    FUN_1001bcd0(puVar9,puVar10,pcVar11);
    FUN_1001b840(this,(int)pcVar6,uVar5,uVar8);
    ExceptionList = local_10;
    return pcVar7;
  }
  FUN_10017fa0();
  pcVar3 = (code *)swi(3);
  pcVar7 = (char *)(*pcVar3)();
  return pcVar7;
}


// FUNCTION_END

// FUNCTION_START: Catch_All@1001b039 @ 1001b039