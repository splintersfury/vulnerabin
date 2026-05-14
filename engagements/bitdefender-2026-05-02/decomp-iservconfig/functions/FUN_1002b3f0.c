int * __thiscall FUN_1002b3f0(void *this,int *param_1,int *param_2)

{
  int *piVar1;
  int iVar2;
  code *pcVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int *piVar7;
  int *piVar8;
  int *piVar9;
  int *piVar10;
  uint uVar11;
  
                    /* WARNING: Load size is inaccurate */
  iVar2 = *this;
  iVar4 = (*(int *)((int)this + 4) - iVar2) / 0x18;
  if (iVar4 != 0xaaaaaaa) {
    uVar11 = (*(int *)((int)this + 8) - iVar2) / 0x18;
    if (0xaaaaaaa - (uVar11 >> 1) < uVar11) {
      uVar11 = 0xaaaaaaa;
    }
    else {
      uVar11 = (uVar11 >> 1) + uVar11;
      if (uVar11 < iVar4 + 1U) {
        uVar11 = iVar4 + 1U;
      }
    }
    piVar7 = (int *)FUN_1002b390(uVar11);
    piVar1 = piVar7 + (((int)param_1 - iVar2) / 0x18) * 6;
    *piVar1 = 0;
    piVar1[4] = 0;
    piVar1[5] = 0;
    iVar2 = param_2[1];
    iVar5 = param_2[2];
    iVar6 = param_2[3];
    *piVar1 = *param_2;
    piVar1[1] = iVar2;
    piVar1[2] = iVar5;
    piVar1[3] = iVar6;
    *(undefined8 *)(piVar1 + 4) = *(undefined8 *)(param_2 + 4);
    param_2[4] = 0;
    param_2[5] = 7;
    *(undefined2 *)param_2 = 0;
    piVar10 = *(int **)((int)this + 4);
                    /* WARNING: Load size is inaccurate */
    piVar9 = *this;
    piVar8 = piVar7;
    if (param_1 != piVar10) {
      FUN_1002b580(*this,param_1,piVar7);
      piVar8 = piVar1 + 6;
      piVar10 = *(int **)((int)this + 4);
      piVar9 = param_1;
    }
    FUN_1002b580(piVar9,piVar10,piVar8);
    FUN_1002b300(this,(int)piVar7,iVar4 + 1,uVar11);
    return piVar1;
  }
  FUN_10017fa0();
  pcVar3 = (code *)swi(3);
  piVar8 = (int *)(*pcVar3)();
  return piVar8;
}


// FUNCTION_END

// FUNCTION_START: FUN_1002b510 @ 1002b510