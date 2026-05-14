uint * __thiscall
FUN_10004850(void *this,uint *param_1,uint param_2,int param_3,uint param_4,int param_5,
            undefined4 param_6,undefined4 param_7,uint param_8)

{
  int iVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  
  uVar8 = param_2 + param_4;
  uVar4 = param_3 + param_5 + (uint)CARRY4(param_2,param_4);
  iVar1 = **(int **)((int)this + 0x1c);
  if ((*(byte *)((int)this + 0x3c) & 2) == 0) {
    uVar6 = **(uint **)((int)this + 0x20);
    if ((uVar6 != 0) && (*(uint *)((int)this + 0x38) < uVar6)) {
      *(uint *)((int)this + 0x38) = uVar6;
    }
  }
  else {
    uVar6 = 0;
  }
  iVar2 = **(int **)((int)this + 0xc);
  iVar3 = *(int *)((int)this + 0x38);
  iVar5 = iVar3 - iVar2;
  uVar7 = iVar5 >> 0x1f;
  if (((uVar7 < uVar4) || ((uVar7 <= uVar4 && ((uint)(iVar5 >> 1) < uVar8)))) ||
     ((uVar8 != 0 || uVar4 != 0 &&
      ((((param_8 & 1) != 0 && (iVar1 == 0)) || (((param_8 & 2) != 0 && (uVar6 == 0)))))))) {
    *param_1 = 0xffffffff;
    param_1[1] = 0xffffffff;
  }
  else {
    if (((param_8 & 1) != 0) && (iVar1 != 0)) {
      **(int **)((int)this + 0x1c) = iVar2 + uVar8 * 2;
      **(int **)((int)this + 0x2c) = (int)(iVar3 - (iVar2 + uVar8 * 2)) >> 1;
    }
    if (((param_8 & 2) != 0) && (uVar6 != 0)) {
      iVar1 = **(int **)((int)this + 0x30);
      iVar3 = **(int **)((int)this + 0x20);
      **(int **)((int)this + 0x10) = iVar2;
      iVar2 = iVar2 + uVar8 * 2;
      **(int **)((int)this + 0x20) = iVar2;
      **(int **)((int)this + 0x30) = (iVar3 + iVar1 * 2) - iVar2 >> 1;
    }
    *param_1 = uVar8;
    param_1[1] = uVar4;
  }
  param_1[2] = 0;
  param_1[3] = 0;
  param_1[4] = 0;
  param_1[5] = 0;
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: FUN_10004990 @ 10004990