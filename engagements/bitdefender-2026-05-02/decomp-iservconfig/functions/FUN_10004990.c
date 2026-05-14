void __thiscall
FUN_10004990(void *this,uint *param_1,uint param_2,int param_3,int param_4,byte param_5)

{
  int iVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  int iVar7;
  uint uVar8;
  uint uVar9;
  uint local_20;
  uint uStack_1c;
  
  iVar1 = **(int **)((int)this + 0x1c);
  if ((*(byte *)((int)this + 0x3c) & 2) == 0) {
    uVar5 = **(uint **)((int)this + 0x20);
    if ((uVar5 != 0) && (*(uint *)((int)this + 0x38) < uVar5)) {
      *(uint *)((int)this + 0x38) = uVar5;
    }
  }
  else {
    uVar5 = 0;
  }
  iVar2 = **(int **)((int)this + 0xc);
  iVar3 = *(int *)((int)this + 0x38);
  iVar7 = iVar3 - iVar2;
  uVar8 = iVar7 >> 1;
  uVar6 = iVar7 >> 0x1f;
  if (param_4 == 0) {
    uStack_1c = 0;
    local_20 = 0;
LAB_10004a5e:
    uVar9 = local_20 + param_2;
    uVar4 = uStack_1c + param_3 + (uint)CARRY4(local_20,param_2);
    if (((uVar4 <= uVar6) && ((uVar4 < uVar6 || (uVar9 <= uVar8)))) &&
       ((uVar9 == 0 && uVar4 == 0 ||
        ((((param_5 & 1) == 0 || (iVar1 != 0)) && (((param_5 & 2) == 0 || (uVar5 != 0)))))))) {
      iVar7 = iVar2 + uVar9 * 2;
      if (((param_5 & 1) != 0) && (iVar1 != 0)) {
        **(int **)((int)this + 0x1c) = iVar7;
        **(int **)((int)this + 0x2c) = iVar3 - iVar7 >> 1;
      }
      if (((param_5 & 2) != 0) && (uVar5 != 0)) {
        iVar1 = **(int **)((int)this + 0x30);
        iVar3 = **(int **)((int)this + 0x20);
        **(int **)((int)this + 0x10) = iVar2;
        **(int **)((int)this + 0x20) = iVar7;
        **(int **)((int)this + 0x30) = (iVar3 + iVar1 * 2) - iVar7 >> 1;
      }
      *param_1 = uVar9;
      param_1[1] = uVar4;
      goto LAB_10004b20;
    }
  }
  else if (param_4 == 1) {
    if ((param_5 & 3) != 3) {
      if ((param_5 & 1) == 0) {
        if (((param_5 & 2) != 0) && ((uVar5 != 0 || (iVar2 == 0)))) {
          uStack_1c = (int)(uVar5 - iVar2) >> 0x1f;
          local_20 = (int)(uVar5 - iVar2) >> 1;
          goto LAB_10004a5e;
        }
      }
      else if ((iVar1 != 0) || (iVar2 == 0)) {
        uStack_1c = iVar1 - iVar2 >> 0x1f;
        local_20 = iVar1 - iVar2 >> 1;
        goto LAB_10004a5e;
      }
    }
  }
  else {
    uStack_1c = uVar6;
    local_20 = uVar8;
    if (param_4 == 2) goto LAB_10004a5e;
  }
  *param_1 = 0xffffffff;
  param_1[1] = 0xffffffff;
LAB_10004b20:
  param_1[2] = 0;
  param_1[3] = 0;
  param_1[4] = 0;
  param_1[5] = 0;
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10004b40 @ 10004b40